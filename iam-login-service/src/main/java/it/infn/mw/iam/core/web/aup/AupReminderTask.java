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

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Component
public class AupReminderTask {

  @Autowired
  IamAccountRepository accounts;

  @Autowired
  IamAupRepository aupRepo;

  @Autowired
  NotificationFactory notification;

  @Autowired
  IamAupSignatureRepository aupSignatureRepo;

  @Autowired
  IamEmailNotificationRepository emailNotificationRepo;

  public void sendAupReminders() {
    aupRepo.findDefaultAup().ifPresent(aup -> {
      LocalDate currentDate = LocalDate.now();
      if (aup.getSignatureValidityInDays() > 0) {
        LocalDate expirationDate = currentDate.minusDays(aup.getSignatureValidityInDays());
        Date expirationDateAsDate = toDate(expirationDate);
        Date expirationDatePlusOneDayAsDate = toDate(expirationDate.plusDays(1));
        List<Integer> reminderIntervals = parseReminderIntervals(aup.getAupRemindersInDays());

        reminderIntervals.forEach(
            interval -> processRemindersForInterval(aup, currentDate, interval, expirationDate));

        List<IamAupSignature> expiredSignatures = aupSignatureRepo.findByAupAndSignatureTime(aup,
            expirationDateAsDate, expirationDatePlusOneDayAsDate);

        // check if an email of type AUP_EXPIRATION does not already exist, because it is never deleted
        expiredSignatures.forEach(s -> {
          if (isExpiredSignatureEmailNotAlreadySentFor(s.getAccount())) {
            notification.createAupSignatureExpMessage(s.getAccount());
          }
        });
      }
    });
  }

  private void processRemindersForInterval(IamAup aup, LocalDate currentDate, Integer interval,
      LocalDate expirationDate) {
    LocalDate reminderDate = expirationDate.plusDays(interval);
    Date reminderDateAsDate = toDate(reminderDate);
    Date reminderDatePlusOneAsDate = toDate(reminderDate.plusDays(1));
    Date tomorrowAsDate = toDate(currentDate.plusDays(1));

    List<IamAupSignature> signatures = aupSignatureRepo.findByAupAndSignatureTime(aup,
        reminderDateAsDate, reminderDatePlusOneAsDate);

    // check if an email of type AUP_REMINDER does not already exist, because it is never deleted
    signatures.forEach(s -> {
      if (isAupReminderEmailNotAlreadySentFor(s.getAccount(), tomorrowAsDate)) {
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

  private Date toDate(LocalDate localDate) {
    return Date.from(localDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
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
