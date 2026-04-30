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
package it.infn.mw.iam.core.web.aup;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Component
public class AupReminderTask {

  private final Clock clock;
  private final IamAupRepository aupRepo;
  private final NotificationFactory notification;
  private final IamAupSignatureRepository aupSignatureRepo;
  private final IamEmailNotificationRepository emailNotificationRepo;

  public AupReminderTask(Clock clock, NotificationFactory notification, IamAupRepository aupRepo,
      IamEmailNotificationRepository emailNotificationRepo,
      IamAupSignatureRepository aupSignatureRepo) {

    this.clock = clock;
    this.notification = notification;
    this.aupRepo = aupRepo;
    this.emailNotificationRepo = emailNotificationRepo;
    this.aupSignatureRepo = aupSignatureRepo;
  }

  public void sendAupReminders() {
    aupRepo.findDefaultAup().ifPresent(aup -> {

      Instant currentInstant = clock.instant();

      if (aup.getSignatureValidityInDays() > 0) {

        Instant signatureTarget = clock.instant().minus(Duration.ofDays(aup.getSignatureValidityInDays())).truncatedTo(ChronoUnit.DAYS);
        Date signatureMin = Date.from(signatureTarget);
        Date signatureMax = Date.from(signatureTarget.plus(Duration.ofDays(1)));
        List<Integer> reminderIntervals = parseReminderIntervals(aup.getAupRemindersInDays());

        reminderIntervals.forEach(
            interval -> processRemindersForInterval(aup, currentInstant, interval, signatureTarget));

        List<IamAupSignature> expiredSignatures = aupSignatureRepo.findByAupAndSignatureTime(aup,
            signatureMin, signatureMax);

        // check if an email of type AUP_EXPIRATION does not already exist, because it is never deleted
        expiredSignatures.forEach(s -> {
          if (isExpiredSignatureEmailNotAlreadySentFor(s.getAccount()) && !s.getAccount().isServiceAccount()) {
            notification.createAupSignatureExpMessage(s.getAccount());
          }
        });
      }
    });
  }

  private void processRemindersForInterval(IamAup aup, Instant currentDate, Integer interval,
      Instant expirationDate) {

    Date signatureMin = Date.from(expirationDate.plus(Duration.ofDays(interval)).truncatedTo(ChronoUnit.DAYS));
    Date signatureMax = Date.from(expirationDate.plus(Duration.ofDays(interval + 1L)).truncatedTo(ChronoUnit.DAYS));
    Date tomorrow = Date.from(currentDate.plus(Duration.ofDays(1)).truncatedTo(ChronoUnit.DAYS));

    List<IamAupSignature> signatures = aupSignatureRepo.findByAupAndSignatureTime(aup,
        signatureMin, signatureMax);

    // check if an email of type AUP_REMINDER does not already exist, because it is never deleted
    signatures.forEach(s -> {
      if (isAupReminderEmailNotAlreadySentFor(s.getAccount(), tomorrow) && !s.getAccount().isServiceAccount()) {
        notification.createAupReminderMessage(s.getAccount(), aup);
      }
    });
  }

  public boolean isExpiredSignatureEmailNotAlreadySentFor(IamAccount account) {
    return emailNotificationRepo
      .countAupExpirationMessPerAccount(account.getUserInfo().getEmail()) == 0;
  }

  public boolean isAupReminderEmailNotAlreadySentFor(IamAccount account, Date tomorrowAsDate) {
    return emailNotificationRepo.countAupRemindersPerAccount(account.getUserInfo().getEmail(),
        tomorrowAsDate) == 0;
  }

  private static List<Integer> parseReminderIntervals(String aupRemindersInDays) {
    List<Integer> result = new ArrayList<>();
    String[] parts = aupRemindersInDays.split("\\s*,\\s*");
    for (String part : parts) {
      result.add(Integer.parseInt(part.trim()));
    }
    return result;
  }

}
