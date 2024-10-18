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
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_IGNORE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_SKIP_EMAIL_SYNCH;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
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
    return voPerson(personId, LocalDate.now().plusDays(365).toDate());
  }

  default VOPersonDTO voPerson(String personId, Date endDate) {
    IamAccount account = IamAccount.newAccount();
    account.getUserInfo().setGivenName("TEST");
    account.getUserInfo().setFamilyName("USER");
    account.getUserInfo().setEmail("test@hr.cern");
    return voPerson(personId, account, "test", endDate);
  }

  default VOPersonDTO noParticipationsVoPerson(String personId) {
    VOPersonDTO dto = voPerson(personId);
    dto.getParticipations().clear();
    return dto;
  }

  default VOPersonDTO expiredVoPerson(String personId) {
    VOPersonDTO dto = voPerson(personId);
    // Set endDate more than 7 days (suspension grace period) but less than 30 days (removal grace
    // period)
    dto.getParticipations().iterator().next().setEndDate(Date.from(NOW.minus(20, ChronoUnit.DAYS)));
    return dto;
  }

  default VOPersonDTO removedVoPerson(String personId) {
    VOPersonDTO dto = voPerson(personId);
    // Set endDate more than 30 days (removal grace period)
    dto.getParticipations().iterator().next().setEndDate(Date.from(NOW.minus(40, ChronoUnit.DAYS)));
    return dto;
  }

  default VOPersonDTO voPerson(String personId, IamAccount account, String experiment,
      Date endDate) {
    VOPersonDTO dto = new VOPersonDTO();
    dto.setFirstName(account.getUserInfo().getGivenName());
    dto.setName(account.getUserInfo().getName());
    dto.setEmail(account.getUserInfo().getEmail());
    dto.setParticipations(Sets.newHashSet());

    dto.setId(Long.parseLong(personId));

    ParticipationDTO p = new ParticipationDTO();

    p.setExperiment(experiment);
    p.setStartDate(endDate);

    InstituteDTO i = new InstituteDTO();
    i.setId("000001");
    i.setName("INFN");
    i.setCountry("IT");
    i.setTown("Bologna");
    p.setInstitute(i);

    dto.getParticipations().add(p);

    return dto;
  }

  default Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

}
