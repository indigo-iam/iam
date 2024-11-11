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

import static java.util.Comparator.comparing;
import static java.util.Comparator.naturalOrder;
import static java.util.Comparator.nullsLast;

import java.util.Comparator;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.joda.time.DateTimeComparator;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Status;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;

@Component
@Profile("cern")
public class CernHrLifecycleUtils {

  public static final String LABEL_CERN_PREFIX = "hr.cern";
  public static final String LABEL_STATUS = "status";
  public static final String LABEL_TIMESTAMP = "timestamp";
  public static final String LABEL_MESSAGE = "message";
  public static final String LABEL_ACTION = "action";
  public static final String LABEL_IGNORE = "ignore";
  public static final String LABEL_SKIP_EMAIL_SYNCH = "skip-email-synch";

  public boolean isSkipEmailSynch(IamAccount a) {

    return a.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_SKIP_EMAIL_SYNCH).isPresent();
  }

  public IamLabel buildCernActionLabel() {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_ACTION).build();
  }

  public IamLabel buildCernStatusLabel(Status status) {

    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_STATUS)
      .value(status.name())
      .build();
  }

  public IamLabel buildCernTimestampLabel() {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_TIMESTAMP).build();
  }

  public IamLabel buildCernIgnoreLabel() {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_IGNORE).build();
  }

  public IamLabel buildCernMessageLabel(String message) {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_MESSAGE).value(message).build();
  }

  public Optional<ParticipationDTO> getLastActiveExperimentParticipation(Set<ParticipationDTO> participations,
      String experimentName) {

    Comparator<ParticipationDTO> comparator =
        nullsLast(comparing(ParticipationDTO::getEndDate, nullsLast(naturalOrder())).reversed());

    return participations.stream()
      .filter(p -> p.getExperiment().equalsIgnoreCase(experimentName))
      .sorted(comparator).findFirst();
  }

  public boolean isValidExperimentParticipation(ParticipationDTO participation) {
    if (Objects.isNull(participation.getEndDate())) {
      return true;
    }
    return DateTimeComparator.getDateOnlyInstance()
      .compare(participation.getEndDate(), new Date()) >= 0;
  }
}
