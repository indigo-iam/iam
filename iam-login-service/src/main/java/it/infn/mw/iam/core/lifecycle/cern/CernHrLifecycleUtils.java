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
import static java.util.Comparator.comparing;
import static java.util.Comparator.naturalOrder;
import static java.util.Comparator.nullsLast;

import java.util.Comparator;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import org.joda.time.DateTimeComparator;

import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.CernStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;

public class CernHrLifecycleUtils {

  public static final String LABEL_CERN_PREFIX = "hr.cern";
  public static final String LABEL_STATUS = "status";
  public static final String LABEL_TIMESTAMP = "timestamp";
  public static final String LABEL_MESSAGE = "message";
  public static final String LABEL_ACTION = "action";
  public static final String LABEL_IGNORE = "ignore";
  public static final String LABEL_SKIP_EMAIL_SYNCH = "skip-email-synch";
  public static final String LABEL_SKIP_END_DATE_SYNCH = "skip-end-date-synch";

  private CernHrLifecycleUtils() {}

  public static IamLabel buildCernActionLabel() {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_ACTION).build();
  }

  public static IamLabel buildCernStatusLabel(CernStatus status) {

    return IamLabel.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(LABEL_STATUS)
      .value(status.name())
      .build();
  }

  public static IamLabel buildCernTimestampLabel() {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_TIMESTAMP).build();
  }

  public static IamLabel buildCernIgnoreLabel() {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_IGNORE).build();
  }

  public static IamLabel buildCernMessageLabel(String message) {

    return IamLabel.builder().prefix(LABEL_CERN_PREFIX).name(LABEL_MESSAGE).value(message).build();
  }

  public static IamLabel buildLifecycleStatusLabel() {
    return IamLabel.builder().name(LIFECYCLE_STATUS_LABEL).build();
  }

  public static IamLabel buildLifecycleStatusLabel(AccountLifecycleStatus status) {
    return IamLabel.builder()
      .name(ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL)
      .value(status.name())
      .build();
  }

  public static Optional<ParticipationDTO> getMostRecentMembership(Set<ParticipationDTO> p,
      String experimentName) {
    Comparator<ParticipationDTO> comparator =
        nullsLast(comparing(ParticipationDTO::getEndDate, nullsLast(naturalOrder())).reversed());
    return p.stream()
      .filter(c -> c.getExperiment().equalsIgnoreCase(experimentName))
      .sorted(comparator)
      .findFirst();
  }

  public static boolean isActiveMembership(Date endTime) {
    if (endTime == null) {
      return true;
    }
    return DateTimeComparator.getDateOnlyInstance().compare(endTime, new Date()) >= 0;
  }

  public static boolean isAccountIgnored(IamAccount a) {
    return a.hasLabel(buildCernIgnoreLabel());
  }
}
