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
package it.infn.mw.iam.core.lifecycle;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties.InactiveAccountsTaskProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;

@Component
public class InactiveAccountsTask implements Runnable {

  public static final Logger LOG = LoggerFactory.getLogger(InactiveAccountsTask.class);

  public static final int PAGE_SIZE = 10;

  private final Clock clock;
  private final LifecycleProperties properties;
  private final IamAccountRepository accountRepo;
  private final IamAccountService accountService;
  private final NotificationFactory notificationFactory;
  private final IamEmailNotificationRepository notificationRepo;

  public InactiveAccountsTask(Clock clock, LifecycleProperties properties,
      IamAccountRepository accountRepo, IamAccountService accountService,
      NotificationFactory notificationFactory, IamEmailNotificationRepository notificationRepo) {
    this.clock = clock;
    this.properties = properties;
    this.accountRepo = accountRepo;
    this.accountService = accountService;
    this.notificationFactory = notificationFactory;
    this.notificationRepo = notificationRepo;
  }

  private Date referenceDate(IamAccount account) {
    return account.getLastLoginTime() != null
        ? account.getLastLoginTime()
        : account.getCreationTime();
  }

  private boolean warningNotYetSentThisCycle(IamAccount account) {
    Date since = referenceDate(account);
    return notificationRepo.countInactivityWarningsPerAccount(
        account.getUserInfo().getEmail(), since) == 0;
  }

  public void handleInactiveAccounts() {
    InactiveAccountsTaskProperties taskProperties =
        properties.getAccount().getInactiveAccountsTask();

    if (!taskProperties.isRemoveInactiveAccounts()) {
      return;
    }

    if (properties.getAccount().getInactiveAccountDays() == null) {
      LOG.warn("Inactive accounts task is enabled but lifecycle.account.inactive-account-days is not set");
      return;
    }

    LOG.info("Inactive accounts task ... [START]");

    Instant now = clock.instant();
    long inactivityDays = properties.getAccount().getInactiveAccountDays();
    long gracePeriodDays = taskProperties.getSuspensionGracePeriodDays();

    Date inactivityThreshold = Date.from(now.minus(inactivityDays, ChronoUnit.DAYS));
    Date suspensionThreshold =
        Date.from(now.minus(inactivityDays + gracePeriodDays, ChronoUnit.DAYS));

    List<IamAccount> accountsToSuspend = new ArrayList<>();

    Pageable pageRequest = PageRequest.of(0, PAGE_SIZE, Sort.by(Direction.ASC, "creationTime"));

    while (true) {
      Page<IamAccount> page =
          accountRepo.findInactiveAccountsSince(inactivityThreshold, pageRequest);

      if (page.hasContent()) {
        for (IamAccount account : page.getContent()) {
          Date ref = referenceDate(account);
          if (ref.before(suspensionThreshold)) {
            accountsToSuspend.add(account);
          } else if (warningNotYetSentThisCycle(account)) {
            notificationFactory.createInactivityWarningMessage(account, gracePeriodDays);
            LOG.info("Inactivity warning sent for account {}", account.getUsername());
          }
        }
      }

      if (!page.hasNext()) {
        break;
      }

      pageRequest = page.nextPageable();
    }

    for (IamAccount account : accountsToSuspend) {
      LOG.info("Suspending inactive account {}", account.getUsername());
      accountService.disableAccount(account);
    }

    LOG.info("Inactive accounts task ... [END]");
  }

  @Override
  public void run() {
    handleInactiveAccounts();
  }
}
