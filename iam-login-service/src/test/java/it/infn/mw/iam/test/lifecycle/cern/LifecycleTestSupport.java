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
package it.infn.mw.iam.test.lifecycle.cern;

import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_IGNORE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_SKIP_EMAIL_SYNCH;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_SKIP_END_DATE_SYNCH;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import java.util.function.Supplier;

import org.joda.time.LocalDate;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.registration.cern.dto.InstituteDTO;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;

public interface LifecycleTestSupport {

  String CERN_SSO_ISSUER = "https://auth.cern.ch/auth/realms/cern";
  String CERN_PERSON_ID = "12345678";

  Instant LAST_MIDNIGHT = Instant.now().truncatedTo(ChronoUnit.DAYS);
  Instant NOW = LAST_MIDNIGHT.plus(12, ChronoUnit.HOURS);
  Instant DAY_BEFORE = LAST_MIDNIGHT.minus(1, ChronoUnit.SECONDS);

  Instant ONE_MINUTE_AGO = NOW.minus(1, ChronoUnit.MINUTES);
  Instant FOUR_DAYS_AGO = NOW.minus(4, ChronoUnit.DAYS);
  Instant EIGHT_DAYS_AGO = NOW.minus(8, ChronoUnit.DAYS);
  Instant THIRTY_ONE_DAYS_AGO = NOW.minus(31, ChronoUnit.DAYS);

  default IamLabel cernIgnoreLabel() {
    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_IGNORE).build();
  }


  default IamLabel skipEmailSyncLabel() {
    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_SKIP_EMAIL_SYNCH).build();
  }

  default IamLabel skipEndDateSyncLabel() {
    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_SKIP_END_DATE_SYNCH).build();
  }

  default IamLabel cernPersonIdLabel() {
    return cernPersonIdLabel(CERN_PERSON_ID);
  }

  default IamLabel cernPersonIdLabel(String personId) {
    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name("cern_person_id")
      .value(personId)
      .build();
  }

  default IamLabel statusLabel(AccountLifecycleStatus s) {
    return IamLabel.builder().name(LIFECYCLE_STATUS_LABEL).value(s.name()).build();
  }

  default VOPersonDTO voPerson(String personId) {
    return voPerson(personId, getTestAccount(), getTestParticipations());
  }

  default VOPersonDTO voPerson(String personId, Date endDate) {
    Date startDate = endDate == null ? LocalDate.now().minusDays(365).toDate()
        : LocalDate.fromDateFields(endDate).minusDays(365).toDate();
    return voPerson(personId, getTestAccount(),
        Sets.newHashSet(getParticipation("test", startDate, endDate)));
  }

  default VOPersonDTO noParticipationsVoPerson(String personId) {
    return voPerson(personId, getTestAccount(), Sets.newHashSet());
  }

  default VOPersonDTO expiredVoPerson(String personId) {
    return voPerson(personId, getTestAccount(),
        Sets.newHashSet(getExpiredParticipation("test", 20)));
  }

  default VOPersonDTO removedVoPerson(String personId) {
    return voPerson(personId, getTestAccount(),
        Sets.newHashSet(getExpiredParticipation("test", 40)));
  }

  default VOPersonDTO noEmailVoPerson(String personId) {
    VOPersonDTO personDTO = voPerson(personId);
    personDTO.setEmail(null);
    return personDTO;
  }

  default InstituteDTO getTestInstitute() {
    InstituteDTO i = new InstituteDTO();
    i.setId("000001");
    i.setName("Istituto Nazionale di Fisica Nucleare");
    i.setCountry("IT");
    i.setTown("Bologna");
    return i;
  }

  default IamAccount getTestAccount() {
    IamAccount account = IamAccount.newAccount();
    account.getUserInfo().setGivenName("TEST");
    account.getUserInfo().setFamilyName("USER");
    account.getUserInfo().setEmail("test@hr.cern");
    return account;
  }

  default ParticipationDTO getUnlimitedParticipation(String experiment) {
    Date startDate = LocalDate.now().minusDays(365).toDate();
    return getParticipation(experiment, startDate, null);
  }

  default ParticipationDTO getLimitedParticipation(String experiment) {
    Date startDate = LocalDate.now().minusDays(365).toDate();
    Date endDate = LocalDate.now().plusDays(365).toDate();
    return getParticipation(experiment, startDate, endDate);
  }

  default Set<ParticipationDTO> getTestParticipations() {
    return Sets.newHashSet(getLimitedParticipation("test"));
  }

  default ParticipationDTO getParticipation(String experiment, Date startDate, Date endDate) {
    ParticipationDTO p = new ParticipationDTO();
    p.setExperiment(experiment);
    p.setStartDate(startDate);
    p.setEndDate(endDate);
    p.setInstitute(getTestInstitute());
    return p;
  }

  default ParticipationDTO getExpiredParticipation(String experiment, int daysAgo) {
    ParticipationDTO p = new ParticipationDTO();
    p.setExperiment(experiment);
    p.setStartDate(LocalDate.now().minusDays(daysAgo + 365).toDate());
    p.setEndDate(LocalDate.now().minusDays(daysAgo).toDate());
    p.setInstitute(getTestInstitute());
    return p;
  }

  default VOPersonDTO voPerson(String personId, IamAccount account,
      Set<ParticipationDTO> participations) {
    VOPersonDTO dto = new VOPersonDTO();
    dto.setFirstName(account.getUserInfo().getGivenName());
    dto.setName(account.getUserInfo().getName());
    dto.setEmail(account.getUserInfo().getEmail());
    dto.setId(Long.parseLong(personId));
    dto.setParticipations(participations);
    return dto;
  }

  default Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

}
