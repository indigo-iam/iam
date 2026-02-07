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
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.lifecycle.cern.LifecycleTestSupport;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class})
@TestPropertySource(
  properties = {"lifecycle.account.expiredAccountPolicy.suspensionGracePeriodDays=7",
    "lifecycle.account.expiredAccountPolicy.removalGracePeriodDays=30",
    "lifecycle.account.expiredAccountPolicy.removeExpiredAccounts=true"})
@Transactional
class AccountLifecycleTests implements LifecycleTestSupport {

  static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";
  static final String EXPECTED_GROUP_NOT_FOUND = "Expected group not found";

  static final String USER_UUID = UUID.randomUUID().toString();
  static final String USER_USERNAME = "test-account-lifecycle";

  @Autowired
  IamAccountRepository repo;

  @Autowired
  IamAccountService accountService;

  @Autowired
  ExpiredAccountsHandler handler;

  @Autowired
  SecurityContextUtils sc;

  @Autowired
  MutableClock clock;

  IamAccount testAccount;
  Optional<IamLabel> statusLabel;

  private IamAccount getLifecycleAccount() {

    IamAccount a = IamAccount.newAccount();
    a.setUuid(USER_UUID);
    a.setUsername(USER_USERNAME);
    a.setActive(true);
    a.getUserInfo().setGivenName("Test");
    a.getUserInfo().setFamilyName("Test");
    a.getUserInfo().setEmail("test.lifecycle.account@cern.ch");
    a.setEndTime(null);
    a.getLabels().clear();
    return a;
  }

  @BeforeEach
  void createTestAccount() {

    testAccount = accountService.createAccount(getLifecycleAccount());
    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(testAccount.isActive(), is(true));
    assertThat(statusLabel.isPresent(), is(false));
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

}
