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

import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_ACTION;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_IGNORE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_SKIP_EMAIL_SYNCH;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.function.Supplier;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.registration.cern.dto.InstituteDTO;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Action;
import it.infn.mw.iam.persistence.model.IamLabel;

public interface LifecycleTestSupport {

  String CERN_SSO_ISSUER = "https://auth.cern.ch/auth/realms/cern";
  String CERN_PERSON_ID = "12345678";

  Instant NOW = Instant.parse("2020-01-01T00:00:00.00Z");

  Instant FOUR_DAYS_AGO = NOW.minus(4, ChronoUnit.DAYS);
  Instant EIGHT_DAYS_AGO = NOW.minus(8, ChronoUnit.DAYS);
  Instant THIRTY_ONE_DAYS_AGO = NOW.minus(31, ChronoUnit.DAYS);

  default IamLabel cernIgnoreLabel() {
    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_IGNORE)
      .build();
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

  default IamLabel actionLabel(Action a) {
    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_ACTION)
      .value(a.name())
      .build();
  }

  default VOPersonDTO voPerson(String personId) {
    VOPersonDTO dto = new VOPersonDTO();
    dto.setFirstName("TEST");
    dto.setName("USER");
    dto.setEmail("test@hr.cern");
    dto.setParticipations(Sets.newHashSet());

    dto.setId(Long.parseLong(personId));

    ParticipationDTO p = new ParticipationDTO();

    p.setExperiment("test");
    p.setStartDate(Date.from(Instant.parse("2020-01-01T00:00:00.00Z")));

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
