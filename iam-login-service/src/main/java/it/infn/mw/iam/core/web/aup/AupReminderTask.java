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
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.notification.NotificationFactory;
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
      LocalDate now = LocalDate.now();
      LocalDate sign = now.minusDays(aup.getSignatureValidityInDays());
      Date signDate = Date.from(sign.atStartOfDay(ZoneId.systemDefault()).toInstant());
      LocalDate signPlusOne = sign.plusDays(1);
      Date signPlusOneDay = Date.from(signPlusOne.atStartOfDay(ZoneId.systemDefault()).toInstant());
      List<Integer> intervals = parseReminderIntervals(aup.getAupRemindersInDays());

      intervals.forEach(interval -> processRemindersForInterval(aup, now, interval, sign));

      List<IamAupSignature> expiredSignatures =
          aupSignatureRepo.findByAupAndSignatureTime(aup, signDate, signPlusOneDay);
      expiredSignatures.forEach(s -> {
        if (emailNotificationRepo
          .countAupExpirationMessPerAccount(s.getAccount().getUserInfo().getEmail()) == 0) {
          notification.createAupSignatureExpMessage(s.getAccount());
        }
      });
    });

  }

  private void processRemindersForInterval(IamAup aup, LocalDate now, Integer interval,
      LocalDate sign) {
    LocalDate signature = sign.plusDays(interval);
    LocalDate plusOne = signature.plusDays(1);
    Date expected = Date.from(signature.atStartOfDay(ZoneId.systemDefault()).toInstant());
    Date plusOneDate = Date.from(plusOne.atStartOfDay(ZoneId.systemDefault()).toInstant());
    LocalDate tomorrow = now.plusDays(1);
    Date tomorrowDate = Date.from(tomorrow.atStartOfDay(ZoneId.systemDefault()).toInstant());

    List<IamAupSignature> signatures =
        aupSignatureRepo.findByAupAndSignatureTime(aup, expected, plusOneDate);
    signatures.forEach(s -> {
      if (emailNotificationRepo.countAupRemindersPerAccount(s.getAccount().getUserInfo().getEmail(),
          tomorrowDate) == 0) {
        notification.createAupReminderMessage(s.getAccount(), aup);
      }
    });
  }

  private List<Integer> parseReminderIntervals(String aupRemindersInDays) {
    return Arrays.stream(aupRemindersInDays.split(","))
      .map(Integer::valueOf)
      .collect(Collectors.toList());
  }

}
