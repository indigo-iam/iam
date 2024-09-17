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

import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_REMOVAL;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus.SUSPENDED;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Status.ERROR;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Status.EXPIRED;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Status.IGNORED;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Status.MEMBER;
import static java.lang.String.format;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.joda.time.DateTimeComparator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
@Profile("cern")
public class CernHrLifecycleHandler implements Runnable, SchedulingConfigurer {

  public static final String INVALID_ACCOUNT_MESSAGE = "Account has not the mandatory CERN person id label";

  public static final String IGNORE_MESSAGE = "Skipping account as requested by the 'ignore' label";
  public static final String RESTORED_MESSAGE = "Account restored on %s";
  public static final String NO_PARTICIPATION_MESSAGE = "Account end-time not updated: no participation to %s found";
  public static final String EXPIRED_MESSAGE = "Account participation to the experiment is expired";
  public static final String VALID_MESSAGE = "Account has a valid participation to the experiment";

  public static final String HR_DB_API_ERROR = "Account not updated: HR DB error";

  public static final int DEFAULT_PAGE_SIZE = 50;

  protected static final List<String> SUSPENDED_STATUSES =
      Lists.newArrayList(SUSPENDED.name(), PENDING_REMOVAL.name());

  public static final Logger LOG = LoggerFactory.getLogger(CernHrLifecycleHandler.class);

  public enum Status {
    MEMBER, EXPIRED, IGNORED, ERROR
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

  public CernHrLifecycleHandler(Clock clock, CernProperties cernProperties,
      IamAccountRepository accountRepo, IamAccountService accountService, CernHrDBApiService hrDb) {
    this.clock = clock;
    this.cernProperties = cernProperties;
    this.accountRepo = accountRepo;
    this.accountService = accountService;
    this.hrDb = hrDb;
  }

  private IamLabel buildActionLabel() {
    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_ACTION)
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

  private IamLabel buildIamStatusLabel() {
    return IamLabel.builder().name(LIFECYCLE_STATUS_LABEL).build();
  }

  private Optional<ParticipationDTO> syncAccountInformation(IamAccount a, VOPersonDTO p) {

    LOG.debug("Syncing IAM account '{}' with CERN HR record id '{}'", a.getUsername(), p.getId());

    LOG.debug("Updating Given Name for {} to {} ...", a.getUsername(), p.getFirstName());
    a.getUserInfo().setGivenName(p.getFirstName());
    LOG.debug("Updating Family Name for {} to {} ...", a.getUsername(), p.getName());
    a.getUserInfo().setFamilyName(p.getName());

    Optional<IamLabel> skipEmailSyncLabel =
        a.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_SKIP_EMAIL_SYNCH);

    if (skipEmailSyncLabel.isPresent() && LOG.isInfoEnabled()) {
      LOG.debug("Skipping email synchronization for '{}': label '{}' is present", a.getUsername(),
          skipEmailSyncLabel.get().qualifiedName());
    } else {
      Optional<IamAccount> o = accountRepo.findByEmailWithDifferentUUID(p.getEmail(), a.getUuid());
      if (o.isPresent()) {
        LOG.error(
            "Skipping email synchronization for '{}': email already bounded to another user ('{}')",
            a.getUsername(), o.get().getUsername());
      } else {
        LOG.debug("Updating Email for {} to {} ...", a.getUsername(), p.getEmail());
        a.getUserInfo().setEmail(p.getEmail());
      }
    }

    Optional<ParticipationDTO> experimentParticipation =
        getExperimentParticipation(p, cernProperties.getExperimentName());

    if (experimentParticipation.isPresent()) {
      LOG.debug("Updating end-time for {} to {} ...", a.getUsername(),
          experimentParticipation.get().getEndDate());
      a.setEndTime(experimentParticipation.get().getEndDate());
    }
    return experimentParticipation;
  }

  private boolean accountWasSuspendedByIamLifecycleJob(IamAccount a) {
    Optional<IamLabel> statusLabel = a.getLabelByName(LIFECYCLE_STATUS_LABEL);
    return statusLabel.isPresent() && SUSPENDED_STATUSES.contains(statusLabel.get().getValue());
  }

  private String getCernPersonId(IamAccount a) {
    Optional<IamLabel> cernPersonIdLabel =
        a.getLabelByPrefixAndName(LABEL_CERN_PREFIX, cernProperties.getPersonIdClaim());
    if (cernPersonIdLabel.isEmpty()) {
      LOG.error("Account '{}' should have CERN person id label set!", a.getUsername());
      throw new IllegalArgumentException(INVALID_ACCOUNT_MESSAGE);
    }
    return cernPersonIdLabel.get().getValue();
  }

  public void handleAccount(IamAccount account) {

    LOG.debug("Handling account: {}", account);
    String cernPersonId = getCernPersonId(account);
    LOG.debug("Account CERN person id: {}", cernPersonId);

    // 0. Update time-stamp label
    Instant checkTime = clock.instant();
    accountService.setLabel(account, buildTimestampLabel(checkTime));

    // 1. Ignore account if label is set
    if (account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_IGNORE).isPresent()) {
      accountService.setLabel(account, buildStatusLabel(IGNORED));
      accountService.setLabel(account, buildMessageLabel(IGNORE_MESSAGE));
      return;
    }

    // Clear old IAM versions labels
    accountService.deleteLabel(account, buildActionLabel());

    // 2. Retrieve VO person data from HR database
    Optional<VOPersonDTO> voPerson = Optional.empty();
    try {
      voPerson = Optional.ofNullable(hrDb.getHrDbPersonRecord(cernPersonId));
    } catch (RuntimeException e) {
      LOG.error("Error contacting HR DB api: {}", e.getMessage(), e);
    }
    if (Objects.isNull(voPerson) || voPerson.isEmpty()) {
      accountService.setLabel(account, buildStatusLabel(ERROR));
      accountService.setLabel(account, buildMessageLabel(format(HR_DB_API_ERROR)));
      return;
    }

    // 3. Sync info: NAME, EndTime and|or EMAIL
    Optional<ParticipationDTO> experimentParticipation = syncAccountInformation(account, voPerson.get());
    if (experimentParticipation.isEmpty()) {
      accountService.setLabel(account, buildStatusLabel(ERROR));
      accountService.setLabel(account,
          buildMessageLabel(format(NO_PARTICIPATION_MESSAGE, cernProperties.getExperimentName())));
      return;
    }

    if (isValidExperimentParticipation(experimentParticipation.get())) {
      accountService.setLabel(account, buildStatusLabel(MEMBER));
      if (account.isActive()) {
        // 4a. Valid participation and user is not suspended
        accountService.setLabel(account, buildMessageLabel(format(VALID_MESSAGE)));
      } else if (accountWasSuspendedByIamLifecycleJob(account)) {
        // 4b. Valid participation and user has been suspended by IAM expired accounts handler: restore!
        accountService.restoreAccount(account);
        accountService.setLabel(account, buildMessageLabel(format(RESTORED_MESSAGE, checkTime)));
        accountService.deleteLabel(account, buildIamStatusLabel());
      }
    } else {
      // 4c. Invalid participation found: let IAM expired accounts handler do its job
      accountService.setLabel(account, buildStatusLabel(EXPIRED));
      accountService.setLabel(account, buildMessageLabel(format(EXPIRED_MESSAGE)));
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
          try {
            handleAccount(account);
          } catch (RuntimeException e) {
            LOG.error("Error during CERN HR lifecycle handler: {}", e.getMessage());
          }
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

  private Optional<ParticipationDTO> getExperimentParticipation(VOPersonDTO voPerson,
      String experimentName) {
    return voPerson.getParticipations()
      .stream()
      .filter(p -> p.getExperiment().equalsIgnoreCase(experimentName))
      .findFirst();
  }

  private boolean isValidExperimentParticipation(ParticipationDTO participation) {
    if (Objects.isNull(participation.getEndDate())) {
      return true;
    }
    return DateTimeComparator.getDateOnlyInstance()
      .compare(participation.getEndDate(), new Date()) >= 0;
  }
}
