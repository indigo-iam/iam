/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.core.lifecycle.cern;

import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Action.DISABLE_ACCOUNT;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Action.NO_ACTION;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Action.RESTORE_ACCOUNT;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Status.OK;
import static java.lang.String.format;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
@Profile("cern")
public class CernHrLifecycleHandler implements Runnable, SchedulingConfigurer {

  public static final String IGNORE_MESSAGE = "Skipping account as requested by the 'ignore' label";
  public static final String HR_DB_API_ERROR = "Account not updated: HR DB error";
  public static final String PERSON_ID_NOT_FOUND_TEMPLATE = "%s not found";

  public static final int DEFAULT_PAGE_SIZE = 50;

  public static final Logger LOG = LoggerFactory.getLogger(CernHrLifecycleHandler.class);

  public enum Action {
    NO_ACTION,
    DISABLE_ACCOUNT,
    RESTORE_ACCOUNT
  }

  public enum Status {
    OK,
    ERROR
  }

  public static final String LABEL_CERN_PREFIX = "hr.cern";
  public static final String LABEL_STATUS = "status";
  public static final String LABEL_TIMESTAMP = "timestamp";
  public static final String LABEL_MESSAGE = "message";
  public static final String LABEL_ACTION = "action";
  public static final String LABEL_IGNORE = "ignore";
  public static final String LABEL_SKIP_EMAIL_SYNCH = "skip-email-synch";

  private final Clock clock;
  private final CernProperties cernProperties;
  private final IamAccountRepository accountRepo;
  private final IamAccountService accountService;
  private final CernHrDBApiService hrDb;

  @Autowired
  public CernHrLifecycleHandler(Clock clock, CernProperties cernProperties,
      IamAccountRepository accountRepo, IamAccountService accountService, CernHrDBApiService hrDb) {
    this.clock = clock;
    this.cernProperties = cernProperties;
    this.accountRepo = accountRepo;
    this.accountService = accountService;
    this.hrDb = hrDb;
  }

  private Supplier<IllegalArgumentException> personIdNotFound(IamAccount a) {
    return () -> new IllegalArgumentException(
        "CERN person id not found for account " + a.getUsername());
  }

  private IamLabel buildActionLabel(Action action) {
    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_ACTION)
      .value(action.name())
      .build();
  }

  private IamLabel buildStatusLabel(Status status) {
    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_STATUS)
      .value(status.name())
      .build();
  }

  private IamLabel buildTimestampLabel(Instant now) {
    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_TIMESTAMP)
      .value(String.valueOf(now.toEpochMilli()))
      .build();
  }

  private IamLabel buildMessageLabel(String message) {
    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_MESSAGE).value(message).build();
  }

  public void addErrorMessage(IamAccount account, String message) {
    account.getLabels().add(buildStatusLabel(Status.ERROR));
    account.getLabels().add(buildMessageLabel(message));
  }

  private void syncMembershipInformation(IamAccount account) {
    IamLabel cernPersonId = getPersonIdLabel(account).orElseThrow(personIdNotFound(account));

    VOPersonDTO voPerson = hrDb.getHrDbPersonRecord(cernPersonId.getValue());
    LOG.debug("Syncing IAM account {} information against CERN HR db record {}",
        account.getUsername(), voPerson.getId());

    account.getUserInfo().setGivenName(voPerson.getFirstName());
    account.getUserInfo().setFamilyName((voPerson.getName()));

    Optional<IamLabel> skipEmailSyncLabel =
        account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_SKIP_EMAIL_SYNCH);

    if (skipEmailSyncLabel.isPresent() && LOG.isInfoEnabled()) {
      LOG.info(
          "Skipping email synchronization for account '{} ({})' as requested by the label '{}'",
          account.getUsername(), account.getUuid(), skipEmailSyncLabel.get().qualifiedName());
    } else {
      Optional<IamAccount> otherAccount =
          accountRepo.findByEmailWithDifferentUUID(voPerson.getEmail(), account.getUuid());
      if (otherAccount.isPresent()) {
        LOG.error(
            "Email for VO person {} is already mapped to another account: '{}-{}'. Will skip syncing against that email",
            voPerson.getId(), otherAccount.get().getUsername(), otherAccount.get().getUuid());
      } else {
        account.getUserInfo().setEmail(voPerson.getEmail());
      }
    }

  }

  private boolean accountWasSuspendedByCernHrLifecycleJob(IamAccount account) {
    Optional<IamLabel> actionLabel =
        account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);

    return actionLabel.isPresent() && actionLabel.get().getValue().equals(DISABLE_ACCOUNT.name());
  }

  private void disableAccount(IamAccount account) {
    LOG.info("No valid HR record found for account {} -> Disabling account", account.getUsername());

    accountService.disableAccount(account);
    accountService.setAccountEndTime(account, Date.from(clock.instant()));

    accountService.setLabel(account, buildStatusLabel(OK));
    accountService.setLabel(account, buildActionLabel(DISABLE_ACCOUNT));
  }

  private void restoreAccount(IamAccount account) {
    LOG.info("A valid HR record was found for account {} -> restoring account",
        account.getUsername());

    accountService.restoreAccount(account);
    accountService.setAccountEndTime(account, null);

    accountService.setLabel(account, buildStatusLabel(OK));
    accountService.setLabel(account, buildActionLabel(RESTORE_ACCOUNT));
  }

  public void handleValidAccount(IamAccount account) {
    syncMembershipInformation(account);
    if (!account.isActive() && accountWasSuspendedByCernHrLifecycleJob(account)) {
      restoreAccount(account);
    } else {
      accountService.setLabel(account, buildStatusLabel(OK));
      accountService.setLabel(account, buildActionLabel(NO_ACTION));
    }
  }

  public void handleInvalidAccount(IamAccount account) {
    if (account.isActive()) {
      disableAccount(account);
    } else {
      accountService.setLabel(account, buildStatusLabel(OK));
    }
  }

  public void handleIgnoredAccount(IamAccount account) {
    accountService.setLabel(account, buildStatusLabel(OK));
    accountService.setLabel(account, buildActionLabel(NO_ACTION));
    accountService.setLabel(account, buildMessageLabel(IGNORE_MESSAGE));
  }

  private Optional<IamLabel> getPersonIdLabel(IamAccount account) {
    return account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, cernProperties.getPersonIdClaim());
  }

  public void handleAccount(IamAccount account) {
    LOG.debug("Handling account: {}", account);
    Instant checkTime = clock.instant();
    accountService.setLabel(account, buildTimestampLabel(checkTime));
    Optional<IamLabel> cernPersonId = getPersonIdLabel(account);
    if (!cernPersonId.isPresent()) {
      addErrorMessage(account,
          format(PERSON_ID_NOT_FOUND_TEMPLATE, cernProperties.getPersonIdClaim()));
    } else {
      if (account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_IGNORE).isPresent()) {
        handleIgnoredAccount(account);
      } else {
        try {
          if (hrDb.hasValidExperimentParticipation(cernPersonId.get().getValue())) {
            handleValidAccount(account);
          } else {
            handleInvalidAccount(account);
          }
        } catch (RuntimeException e) {
          LOG.error("Error contacting HR DB api: {}", e.getMessage(), e);
          addErrorMessage(account, format(HR_DB_API_ERROR));
        }
      }
    }
  }

  @Override
  public void run() {

    Pageable pageRequest = PageRequest.of(0, cernProperties.getTask().getPageSize());

    while (true) {
      Page<IamAccount> accountsPage = accountRepo.findByLabelPrefixAndName(LABEL_CERN_PREFIX,
          cernProperties.getPersonIdClaim(), pageRequest);

      LOG.debug("accountsPage: {}", accountsPage);

      if (accountsPage.hasContent()) {
        for (IamAccount account : accountsPage.getContent()) {
          handleAccount(account);
        }
      }

      if (!accountsPage.hasNext()) {
        break;
      }

      pageRequest = accountsPage.nextPageable();
    }
  }

  @Override
  public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {

    if (!cernProperties.getTask().isEnabled()) {
      LOG.info("CERN HR DB lifecycle handler is DISABLED");
    } else {
      final String cronSchedule = cernProperties.getTask().getCronSchedule();
      LOG.info("Scheduling CERN HR DB lifecycle handler with schedule: {}", cronSchedule);
      taskRegistrar.addCronTask(this, cronSchedule);
    }
  }
}
