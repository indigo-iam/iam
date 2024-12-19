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
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_SKIP_EMAIL_SYNCH;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_SKIP_END_DATE_SYNCH;
import static java.lang.String.format;

import java.util.Date;
import java.util.List;
import java.util.Optional;

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
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.EmailAlreadyBoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
@Profile("cern")
public class CernHrLifecycleHandler implements Runnable, SchedulingConfigurer {

  public static final String INVALID_ACCOUNT_MESSAGE =
      "Account has not the mandatory CERN person id label";

  public static final String IGNORE_MESSAGE = "Skipping account as requested by the 'ignore' label";
  public static final String NO_PERSON_FOUND_MESSAGE = "No person id %s found on HR DB";
  public static final String NO_PARTICIPATION_MESSAGE =
      "Account end-time not updated: no participation to %s found";
  public static final String SYNCHRONIZED_MESSAGE =
      "Account's membership to the experiment synchronized";

  public static final String HR_DB_API_ERROR = "Account not updated: HR DB error";

  public static final int DEFAULT_PAGE_SIZE = 50;

  protected static final List<String> SUSPENDED_STATUSES =
      Lists.newArrayList(SUSPENDED.name(), PENDING_REMOVAL.name());

  public static final Logger LOG = LoggerFactory.getLogger(CernHrLifecycleHandler.class);

  public enum CernStatus {
    IGNORED, ERROR, EXPIRED, VO_MEMBER
  }

  private final CernProperties cernProperties;
  private final IamAccountRepository accountRepo;
  private final IamAccountService accountService;
  private final CernHrDBApiService hrDb;

  public CernHrLifecycleHandler(CernProperties cernProperties, IamAccountRepository accountRepo,
      IamAccountService accountService, CernHrDBApiService hrDb) {
    this.cernProperties = cernProperties;
    this.accountRepo = accountRepo;
    this.accountService = accountService;
    this.hrDb = hrDb;
  }

  public void handleAccount(String cernPersonId, String experiment, IamAccount a) {

    LOG.debug("Handling IAM account (username: {} , uuid: {})", a.getUsername(), a.getUuid());
    LOG.debug("Synchronize with CERN person id {} ({})", cernPersonId, experiment);

    deleteDeprecatedLabels(a);

    if (CernHrLifecycleUtils.isAccountIgnored(a)) {
      setCernStatusLabel(a, CernStatus.IGNORED, IGNORE_MESSAGE);
      return;
    }

    Optional<VOPersonDTO> voPerson = Optional.empty();
    try {
      voPerson = hrDb.getHrDbPersonRecord(cernPersonId);
    } catch (CernHrDbApiError e) {
      LOG.error("Error contacting HR DB api: {}", e.getMessage(), e);
      setCernStatusLabel(a, CernStatus.ERROR, format(HR_DB_API_ERROR));
      return;
    }
    if (voPerson.isEmpty()) {
      expireIfActiveAndMember(a);
      setCernStatusLabel(a, CernStatus.EXPIRED, format(NO_PERSON_FOUND_MESSAGE, cernPersonId));
      return;
    }

    syncAccountInformation(a, voPerson.get());

    Optional<ParticipationDTO> ep = CernHrLifecycleUtils
      .getMostRecentMembership(voPerson.get().getParticipations(), experiment);

    if (ep.isEmpty()) {
      expireIfActiveAndMember(a);
      setCernStatusLabel(a, CernStatus.EXPIRED, format(NO_PARTICIPATION_MESSAGE, experiment));
      return;
    }

    syncAccountEndTime(a, ep.get().getEndDate());
    setCernStatusLabel(a, CernStatus.VO_MEMBER, format(SYNCHRONIZED_MESSAGE));

    if (CernHrLifecycleUtils.isActiveMembership(a.getEndTime()) && !a.isActive()
        && accountWasSuspendedByIamLifecycleJob(a)) {
      restoreAccount(a);
    }
  }

  private void expireIfActiveAndMember(IamAccount a) {
    if (CernHrLifecycleUtils.isActiveMembership(a.getEndTime()) && a.isActive()) {
      expireAccount(a);
    }
  }

  @Override
  public void run() {

    LOG.info("CERN HR Lyfecycle handler ... [START]");

    Pageable pageRequest = PageRequest.of(0, cernProperties.getTask().getPageSize());

    while (true) {
      Page<IamAccount> accountsPage = accountRepo.findByLabelPrefixAndName(LABEL_CERN_PREFIX,
          cernProperties.getPersonIdClaim(), pageRequest);

      LOG.debug("accountsPage: {}", accountsPage);

      if (accountsPage.hasContent()) {
        for (IamAccount account : accountsPage.getContent()) {
          try {
            handleAccount(getCernPersonId(account), cernProperties.getExperimentName(), account);
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

    LOG.info("CERN HR Lyfecycle handler ... [END]");
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

  private void deleteDeprecatedLabels(IamAccount a) {
    /* remove deprecated labels: to be removed with a migration into next IAM release */
    accountService.deleteLabel(a, CernHrLifecycleUtils.buildCernTimestampLabel());
    accountService.deleteLabel(a, CernHrLifecycleUtils.buildCernActionLabel());
  }

  private void syncAccountInformation(IamAccount a, VOPersonDTO p) {
    accountService.setAccountGivenName(a, p.getFirstName());
    accountService.setAccountFamilyName(a, p.getName());
    if (!isSkipEmailSynch(a)) {
      try {
        accountService.setAccountEmail(a, p.getEmail());
      } catch (EmailAlreadyBoundException e) {
        LOG.error(e.getMessage());
      }
    }
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

  private boolean isSkipEmailSynch(IamAccount a) {
    return a.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_SKIP_EMAIL_SYNCH).isPresent();
  }

  private boolean isSkipEndDateSynch(IamAccount a) {
    return a.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_SKIP_END_DATE_SYNCH).isPresent();
  }

  private void setCernStatusLabel(IamAccount a, CernStatus status, String message) {
    IamLabel statusLabel = CernHrLifecycleUtils.buildCernStatusLabel(status);
    IamLabel messageLabel = CernHrLifecycleUtils.buildCernMessageLabel(message);
    accountService.addLabel(a, statusLabel);
    accountService.addLabel(a, messageLabel);
  }

  private void restoreAccount(IamAccount a) {
    accountService.restoreAccount(a);
    IamLabel statusLabel = CernHrLifecycleUtils.buildLifecycleStatusLabel();
    accountService.deleteLabel(a, statusLabel);
  }

  private void syncAccountEndTime(IamAccount a, Date endDate) {
    if (!isSkipEndDateSynch(a)) {
      accountService.setAccountEndTime(a, endDate);
    }
  }

  private void expireAccount(IamAccount a) {
    accountService.setAccountEndTime(a, new Date());
  }
}
