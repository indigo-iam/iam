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

import static it.infn.mw.iam.core.lifecycle.InactiveAccountsTask.INACTIVITY_WARNING_LABEL;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.time.Duration;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.core.lifecycle.InactiveAccountsTask;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.lifecycle.cern.LifecycleTestSupport;
import it.infn.mw.iam.test.util.clock.MutableClock;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class})
@TestPropertySource(properties = {"lifecycle.account.inactiveAccountDays=180",
    "lifecycle.account.inactiveAccountsTask.suspendInactiveAccounts=true",
    "lifecycle.account.inactiveAccountsTask.suspensionGracePeriodDays=30"})
@Transactional
class InactiveAccountsTaskTests implements LifecycleTestSupport {

  static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";

  static final String USER_UUID = UUID.randomUUID().toString();
  static final String USER_USERNAME = "test-inactive-account";

  @Autowired
  IamAccountRepository repo;

  @Autowired
  IamAccountService accountService;

  @Autowired
  IamEmailNotificationRepository notificationRepo;

  @Autowired
  InactiveAccountsTask task;

  @Autowired
  MutableClock clock;

  IamAccount testAccount;

  private IamAccount getInactiveAccount() {

    IamAccount a = IamAccount.newAccount();
    a.setUuid(USER_UUID);
    a.setUsername(USER_USERNAME);
    a.setActive(true);
    a.getUserInfo().setGivenName("Test");
    a.getUserInfo().setFamilyName("Test");
    a.getUserInfo().setEmail("test.inactive.account@example.org");
    a.setEndTime(null);
    a.getLabels().clear();
    return a;
  }

  private IamAccount reloadAccount() {
    return accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
  }

  private void setLastLoginDaysAgo(long days) {
    testAccount.setLastLoginTime(Date.from(clock.instant().minus(Duration.ofDays(days))));
    repo.save(testAccount);
  }

  private long warningCount() {
    return notificationRepo.findByNotificationType(IamNotificationType.ACCOUNT_INACTIVITY_WARNING)
      .size();
  }

  @BeforeEach
  void createTestAccount() {
    Date recent = Date.from(clock.instant().minus(Duration.ofDays(1)));
    repo.findAll().forEach(a -> {
      a.setLastLoginTime(recent);
      repo.save(a);
    });
    testAccount = accountService.createAccount(getInactiveAccount());
    testAccount.setLastLoginTime(recent);
    repo.save(testAccount);
    clock.advance(Duration.ofHours(1));
  }

  @Test
  void activeAccountIsLeftAlone() {

    setLastLoginDaysAgo(10);
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));
    assertThat(warningCount(), is(0L));
  }

  @Test
  void inactiveAccountIsWarnedOnce() {

    setLastLoginDaysAgo(181);
    task.handleInactiveAccounts();
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));
    assertThat(testAccount.getLabelByName(INACTIVITY_WARNING_LABEL).isPresent(), is(true));
    assertThat(warningCount(), is(1L));
  }

  @Test
  void inactiveAccountIsSuspendedAfterGracePeriod() {

    setLastLoginDaysAgo(181);
    task.handleInactiveAccounts();

    clock.advance(Duration.ofDays(29));
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));

    clock.advance(Duration.ofDays(2));
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(false));
    assertThat(testAccount.getLabelByName(INACTIVITY_WARNING_LABEL).isPresent(), is(false));
    assertThat(warningCount(), is(1L));
  }

  @Test
  void reenabledAccountGetsFreshWarningAndGracePeriod() {

    setLastLoginDaysAgo(181);
    task.handleInactiveAccounts();
    clock.advance(Duration.ofDays(31));
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(false));

    testAccount.setActive(true);
    repo.save(testAccount);
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));
    assertThat(warningCount(), is(2L));

    clock.advance(Duration.ofDays(29));
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));

    clock.advance(Duration.ofDays(2));
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(false));
  }

  @Test
  void loginAfterWarningResetsTheCycle() {

    setLastLoginDaysAgo(181);
    task.handleInactiveAccounts();
    assertThat(warningCount(), is(1L));

    testAccount = reloadAccount();
    testAccount.setLastLoginTime(Date.from(clock.instant()));
    repo.save(testAccount);

    clock.advance(Duration.ofDays(40));
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));
    assertThat(warningCount(), is(1L));
  }

  @Test
  void longInactiveAccountIsWarnedBeforeSuspension() {

    setLastLoginDaysAgo(400);
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));
    assertThat(warningCount(), is(1L));

    clock.advance(Duration.ofDays(31));
    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(false));
  }

  @Test
  void accountThatNeverLoggedInUsesCreationTime() {

    testAccount.setLastLoginTime(null);
    testAccount.setCreationTime(Date.from(clock.instant().minus(Duration.ofDays(181))));
    repo.save(testAccount);

    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));
    assertThat(warningCount(), is(1L));
  }

  @Test
  void serviceAccountsAreIgnored() {

    setLastLoginDaysAgo(400);
    testAccount = reloadAccount();
    testAccount.setServiceAccount(true);
    repo.save(testAccount);

    task.handleInactiveAccounts();

    testAccount = reloadAccount();
    assertThat(testAccount.isActive(), is(true));
    assertThat(warningCount(), is(0L));
  }
}
