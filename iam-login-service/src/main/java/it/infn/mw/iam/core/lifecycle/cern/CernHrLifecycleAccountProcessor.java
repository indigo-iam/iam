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
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.*;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.*;
import static java.lang.String.format;

import java.time.Clock;
import java.util.Date;
import java.util.Optional;

import javax.persistence.EntityNotFoundException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.EmailAlreadyBoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/** Applies a CERN HR snapshot atomically to the current, locked account state. */
@Service
@Profile("cern")
public class CernHrLifecycleAccountProcessor {

  private static final Logger LOG = LoggerFactory.getLogger(CernHrLifecycleAccountProcessor.class);
  private final Clock clock;
  private final IamAccountRepository accountRepo;
  private final IamAccountService accountService;

  public CernHrLifecycleAccountProcessor(Clock clock, IamAccountRepository accountRepo,
      IamAccountService accountService) {
    this.clock = clock;
    this.accountRepo = accountRepo;
    this.accountService = accountService;
  }

  @Transactional
  public void processApiError(String uuid) {
    IamAccount a = lockedAccount(uuid);
    setCernStatusLabel(a, CernStatus.ERROR, HR_DB_API_ERROR);
  }

  @Transactional
  public void process(String uuid, String cernPersonId, String experiment,
      Optional<VOPersonDTO> voPerson) {
    IamAccount a = lockedAccount(uuid);
    LOG.debug("Handling IAM account (username: {}, uuid: {})", a.getUsername(), uuid);
    deleteDeprecatedLabels(a);

    if (CernHrLifecycleUtils.isAccountIgnored(a)) {
      setCernStatusLabel(a, CernStatus.IGNORED, IGNORE_MESSAGE);
      return;
    }

    Date now = Date.from(clock.instant());
    if (voPerson.isEmpty()) {
      setCernStatusLabel(a, CernStatus.EXPIRED, format(NO_PERSON_FOUND_MESSAGE, cernPersonId));
      if (a.isValid(now)) {
        expireAccount(a);
      }
      return;
    }

    syncAccountInformation(a, voPerson.get());
    Optional<ParticipationDTO> ep = CernHrLifecycleUtils
      .getMostRecentMembership(voPerson.get().getParticipations(), experiment);
    if (ep.isEmpty()) {
      setCernStatusLabel(a, CernStatus.EXPIRED, format(NO_PARTICIPATION_MESSAGE, experiment));
      if (a.isValid(now)) {
        expireAccount(a);
      }
      return;
    }

    a.getUserInfo().setAffiliation(ep.get().getInstitute().getName());
    if (CernHrLifecycleUtils.isActiveMembership(clock, ep.get().getEndDate()) && !a.isActive()
        && accountWasSuspendedByIamLifecycleJob(a)) {
      accountService.restoreAccount(a);
      accountService.deleteLabel(a, IamLabel.builder().name(LIFECYCLE_STATUS_LABEL).build());
    }
    syncAccountEndTime(a, ep.get().getEndDate());
    setCernStatusLabel(a, CernStatus.VO_MEMBER, SYNCHRONIZED_MESSAGE);
  }

  private IamAccount lockedAccount(String uuid) {
    return accountRepo.findByUuidForUpdate(uuid)
      .orElseThrow(() -> new EntityNotFoundException("Account not found: " + uuid));
  }

  private void deleteDeprecatedLabels(IamAccount a) {
    accountService.deleteLabel(a, CernHrLifecycleUtils.buildCernTimestampLabel());
    accountService.deleteLabel(a, CernHrLifecycleUtils.buildCernActionLabel());
  }

  private void syncAccountInformation(IamAccount a, VOPersonDTO p) {
    accountService.setAccountGivenName(a, p.getFirstName());
    accountService.setAccountFamilyName(a, p.getName());
    if (!isSkipEmailSynch(a)) {
      try {
        accountService.setAccountEmail(a, p.getEmail());
      } catch (EmailAlreadyBoundException | NullPointerException e) {
        LOG.error("Error on setting email for account {}: {}", a.getUuid(), e.getMessage());
      }
    }
  }

  private boolean accountWasSuspendedByIamLifecycleJob(IamAccount a) {
    Optional<IamLabel> statusLabel = a.getLabelByName(LIFECYCLE_STATUS_LABEL);
    return statusLabel.isPresent() && SUSPENDED_STATUSES.contains(statusLabel.get().getValue());
  }

  private boolean isSkipEmailSynch(IamAccount a) {
    return a.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_SKIP_EMAIL_SYNCH).isPresent();
  }

  private boolean isSkipEndDateSynch(IamAccount a) {
    return a.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_SKIP_END_DATE_SYNCH).isPresent();
  }

  private void setCernStatusLabel(IamAccount a, CernStatus status, String message) {
    accountService.addLabel(a, CernHrLifecycleUtils.buildCernStatusLabel(status));
    accountService.addLabel(a, CernHrLifecycleUtils.buildCernMessageLabel(message));
  }

  private void syncAccountEndTime(IamAccount a, Date endDate) {
    if (!isSkipEndDateSynch(a)) {
      accountService.setAccountEndTime(a, endDate);
    }
  }

  private void expireAccount(IamAccount a) {
    accountService.setAccountEndTime(a, Date.from(clock.instant()));
  }
}
