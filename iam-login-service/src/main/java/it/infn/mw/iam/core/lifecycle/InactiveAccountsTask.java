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
import java.util.Optional;

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
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Component
public class InactiveAccountsTask implements Runnable {

  public static final Logger LOG = LoggerFactory.getLogger(InactiveAccountsTask.class);

  public static final int PAGE_SIZE = 10;

  public static final String INACTIVITY_WARNING_LABEL = "inactivity.warning-time";

  private final Clock clock;
  private final LifecycleProperties properties;
  private final IamAccountRepository accountRepo;
  private final IamAccountService accountService;
  private final NotificationFactory notificationFactory;

  public InactiveAccountsTask(Clock clock, LifecycleProperties properties,
      IamAccountRepository accountRepo, IamAccountService accountService,
      NotificationFactory notificationFactory) {
    this.clock = clock;
    this.properties = properties;
    this.accountRepo = accountRepo;
    this.accountService = accountService;
    this.notificationFactory = notificationFactory;
  }

  private Date referenceDate(IamAccount account) {
    return account.getLastLoginTime() != null
        ? account.getLastLoginTime()
        : account.getCreationTime();
  }

  private Optional<Instant> warningTimeForCurrentCycle(IamAccount account) {
    return account.getLabelByName(INACTIVITY_WARNING_LABEL)
      .map(IamLabel::getValue)
      .flatMap(value -> {
        try {
          return Optional.of(Instant.ofEpochSecond(Long.parseLong(value)));
        } catch (NumberFormatException e) {
          LOG.warn("Ignoring invalid {} label value for account {}: {}",
              INACTIVITY_WARNING_LABEL, account.getUsername(), value);
          return Optional.empty();
        }
      })
      .filter(warningTime -> warningTime.isAfter(referenceDate(account).toInstant()));
  }

  private void sendWarning(IamAccount account, Instant now, long gracePeriodDays) {
    IamEmailNotification notification =
        notificationFactory.createInactivityWarningMessage(account, gracePeriodDays);

    if (notification == null) {
      LOG.error("Could not create inactivity warning message for account {}",
          account.getUsername());
      return;
    }

    accountService.addLabel(account,
        IamLabel.builder()
          .name(INACTIVITY_WARNING_LABEL)
          .value(String.valueOf(now.getEpochSecond()))
          .build());

    LOG.info("Inactivity warning sent for account {}", account.getUsername());
  }

  public void handleInactiveAccounts() {
    InactiveAccountsTaskProperties taskProperties =
        properties.getAccount().getInactiveAccountsTask();

    if (!taskProperties.isSuspendInactiveAccounts()) {
      return;
    }

    if (properties.getAccount().getInactiveAccountDays() == null) {
      LOG.warn(
          "Inactive accounts task is enabled but lifecycle.account.inactive-account-days is not set");
      return;
    }

    LOG.info("Inactive accounts task ... [START]");

    Instant now = clock.instant();
    long inactivityDays = properties.getAccount().getInactiveAccountDays();
    long gracePeriodDays = taskProperties.getSuspensionGracePeriodDays();

    Date inactivityThreshold = Date.from(now.minus(inactivityDays, ChronoUnit.DAYS));
    Instant suspensionThreshold = now.minus(gracePeriodDays, ChronoUnit.DAYS);

    List<IamAccount> accountsToSuspend = new ArrayList<>();

    Pageable pageRequest = PageRequest.of(0, PAGE_SIZE, Sort.by(Direction.ASC, "creationTime"));

    while (true) {
      Page<IamAccount> page =
          accountRepo.findInactiveAccountsSince(inactivityThreshold, pageRequest);

      for (IamAccount account : page.getContent()) {
        Optional<Instant> warningTime = warningTimeForCurrentCycle(account);
        if (warningTime.isEmpty()) {
          sendWarning(account, now, gracePeriodDays);
        } else if (warningTime.get().isBefore(suspensionThreshold)) {
          accountsToSuspend.add(account);
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
  @SchedulerLock(name = "inactiveAccountsTask", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  public void run() {
    handleInactiveAccounts();
  }
}
