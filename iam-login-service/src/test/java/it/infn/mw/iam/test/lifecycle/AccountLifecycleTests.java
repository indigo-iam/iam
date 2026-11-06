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
package it.infn.mw.iam.test.lifecycle;

import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.PendingSuspensionNotificationTask;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.notification.NotificationTestConfig;
import it.infn.mw.iam.test.lifecycle.cern.LifecycleTestSupport;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    ClockConfig.class, NotificationTestConfig.class})
@TestPropertySource(
  properties = {"lifecycle.account.expiredAccountPolicy.suspensionGracePeriodDays=7",
    "lifecycle.account.expiredAccountPolicy.removalGracePeriodDays=30",
    "lifecycle.account.expiredAccountPolicy.removeExpiredAccounts=true",
    "notification.disable=false", "notification.adminAddress=admin@test.example"})
@Transactional
class AccountLifecycleTests implements LifecycleTestSupport {

  static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";

  static final String USER_UUID = UUID.randomUUID().toString();
  static final String USER_USERNAME = "test-account-lifecycle";

  @Autowired
  IamAccountRepository repo;

  @Autowired
  IamAccountService accountService;

  @Autowired
  ExpiredAccountsHandler handler;

  @Autowired
  PendingSuspensionNotificationTask pendingSuspensionNotificationTask;

  @Autowired
  SecurityContextUtils sc;

  @Autowired
  MutableClock clock;

  @Autowired
  IamEmailNotificationRepository notificationRepo;

  @Autowired
  MockNotificationDelivery notificationDelivery;

  IamAccount testAccount;
  Optional<IamLabel> statusLabel;

  private IamAccount getLifecycleAccount(String uuid, String username, String email) {

    IamAccount a = IamAccount.newAccount();
    a.setUuid(uuid);
    a.setUsername(username);
    a.setActive(true);
    a.getUserInfo().setGivenName("Test");
    a.getUserInfo().setFamilyName("Test");
    a.getUserInfo().setEmail(email);
    a.setEndTime(null);
    a.getLabels().clear();
    return a;
  }

  private IamAccount getLifecycleAccount() {
    return getLifecycleAccount(USER_UUID, USER_USERNAME, "test.lifecycle.account@cern.ch");
  }

  @BeforeEach
  void createTestAccount() {

    testAccount = accountService.createAccount(getLifecycleAccount());

    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(testAccount.isActive(), is(true));
    assertThat(statusLabel.isPresent(), is(false));
    clock.advance(Duration.ofHours(1));
  }

  @AfterEach
  void cleanupNotifications() {
    notificationDelivery.clearDeliveredNotifications();
  }

  @Test
  void testUserSuspensionAtLastMidnight() {

    accountService.setAccountEndTime(testAccount, Date.from(clock.lastMidnight()));
    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);

    assertThat(testAccount.isActive(), is(true));
    assertThat(statusLabel.isPresent(), is(false));
  }

  @Test
  void testSuspensionGracePeriodWorks() {

    accountService.setAccountEndTime(testAccount, Date.from(clock.daysBefore(1)));
    testAccount = accountService.findByUuid(USER_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);

    assertThat(testAccount.isActive(), is(true));
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(),
        is(ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_SUSPENSION.name()));

    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
      statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);

      assertThat(testAccount.isActive(), is(true));
      assertThat(statusLabel.isPresent(), is(true));
      assertThat(statusLabel.get().getValue(),
          is(ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_SUSPENSION.name()));
  }

  @Test
  void testRemovalGracePeriodWorks() {

    accountService.setAccountEndTime(testAccount, Date.from(clock.daysBefore(8)));
    Date lastUpdateTime = testAccount.getLastUpdateTime();

    clock.advance(Duration.ofHours(1));
    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));
    assertThat(testAccount.getLastUpdateTime().compareTo(lastUpdateTime) > 0, is(true));
    lastUpdateTime = testAccount.getLastUpdateTime();

    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));
    assertThat(testAccount.getLastUpdateTime().compareTo(lastUpdateTime) == 0, is(true));

    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(),
        is(ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_REMOVAL.name()));
  }

  @Test
  void testAccountRemovalWorks() {

    accountService.setAccountEndTime(testAccount, Date.from(clock.daysBefore(31)));

    handler.handleExpiredAccounts();

    assertThat(accountService.findByUuid(USER_UUID).isEmpty(), is(true));
  }

  @Test
  void testNoAccountsRemoved() {

    long accountBefore = repo.count();

    handler.handleExpiredAccounts();

    long accountAfter = repo.count();

    assertThat(accountBefore, is(accountAfter));
  }

  @Test
  void testPendingSuspensionAdminDigestIsCreatedForPendingAccounts() {

    accountService.setAccountEndTime(testAccount, Date.from(clock.daysBefore(1)));

    IamAccount secondAccount = accountService.createAccount(getLifecycleAccount(
        UUID.randomUUID().toString(), "test-account-lifecycle-2",
        "test.lifecycle.account.2@cern.ch"));
    accountService.setAccountEndTime(secondAccount, Date.from(clock.daysBefore(1)));

    handler.handleExpiredAccounts();

    List<IamEmailNotification> digestNotifications =
        notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_PENDING_SUSPENSION);
    assertThat(digestNotifications, hasSize(0));

    pendingSuspensionNotificationTask.createPendingSuspensionDigest();

    digestNotifications =
        notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_PENDING_SUSPENSION);

    assertThat(digestNotifications, hasSize(1));
    assertThat(digestNotifications.get(0).getReceivers(), hasSize(1));
    assertThat(digestNotifications.get(0).getReceivers().get(0).getEmailAddress(),
        is("admin@test.example"));
    assertThat(digestNotifications.get(0).getBody(),
        containsString("test-account-lifecycle"));
    assertThat(digestNotifications.get(0).getBody(),
        containsString("test-account-lifecycle-2"));
    assertThat(digestNotifications.get(0).getBody(),
        containsString("Expiration date:"));
    assertThat(digestNotifications.get(0).getBody(),
        containsString("Suspension date:"));
    assertThat(digestNotifications.get(0).getBody(),
        containsString("Time left:"));
    // Verify time left includes days, hours, and minutes
    assertThat(digestNotifications.get(0).getBody(),
        containsString("days,"));
    assertThat(digestNotifications.get(0).getBody(),
        containsString("hours,"));
    assertThat(digestNotifications.get(0).getBody(),
        containsString("minutes"));

    notificationDelivery.sendPendingNotifications();

    digestNotifications =
        notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_PENDING_SUSPENSION);
    assertThat(digestNotifications, hasSize(1));
    assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(1));

    pendingSuspensionNotificationTask.createPendingSuspensionDigest();

    digestNotifications =
        notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_PENDING_SUSPENSION);
    assertThat(digestNotifications, hasSize(2));

    clock.advance(Duration.ofDays(1));

    pendingSuspensionNotificationTask.createPendingSuspensionDigest();

    digestNotifications =
        notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_PENDING_SUSPENSION);
    assertThat(digestNotifications, hasSize(3));

    // Verify that only the latest digest is PENDING, older pending ones are SKIPPED
    // (First digest was already delivered, so it's not counted)
    long pendingCount = digestNotifications.stream()
        .filter(n -> n.getDeliveryStatus() == IamDeliveryStatus.PENDING)
        .count();
    long skippedCount = digestNotifications.stream()
        .filter(n -> n.getDeliveryStatus() == IamDeliveryStatus.SKIPPED)
        .count();
    long deliveredCount = digestNotifications.stream()
        .filter(n -> n.getDeliveryStatus() == IamDeliveryStatus.DELIVERED)
        .count();
    assertThat(pendingCount, is(1L));
    assertThat(skippedCount, is(1L));
    assertThat(deliveredCount, is(1L));

    notificationDelivery.sendPendingNotifications();
    assertThat(notificationDelivery.getDeliveredNotifications(), hasSize(2));
  }

  @Test
  void testNoPendingSuspensionDigestCreatedWhenNoAccountsPending() {
    // Don't create any accounts with pending suspension status

    List<IamEmailNotification> digestNotifications =
        notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_PENDING_SUSPENSION);
    assertThat(digestNotifications, hasSize(0));

    // Try to create digest when no accounts are pending
    pendingSuspensionNotificationTask.createPendingSuspensionDigest();

    // Verify no digest was created
    digestNotifications =
        notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_PENDING_SUSPENSION);
    assertThat(digestNotifications, hasSize(0));
  }

}
