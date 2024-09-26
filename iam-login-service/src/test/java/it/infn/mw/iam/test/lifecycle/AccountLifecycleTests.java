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

import java.time.Clock;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.lifecycle.cern.LifecycleTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    AccountLifecycleTests.TestConfig.class})
@TestPropertySource(
    properties = {"lifecycle.account.expiredAccountPolicy.suspensionGracePeriodDays=7",
        "lifecycle.account.expiredAccountPolicy.removalGracePeriodDays=30",
        "lifecycle.account.expiredAccountPolicy.removeExpiredAccounts=true"})
public class AccountLifecycleTests extends TestSupport implements LifecycleTestSupport {

  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    Clock mockClock() {
      return Clock.fixed(NOW, ZoneId.systemDefault());
    }
  }

  @Autowired
  private IamAccountRepository repo;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private ExpiredAccountsHandler handler;

  private static final String USER_UUID = UUID.randomUUID().toString();
  private static final String USER_USERNAME = "test-account-lifecycle";
  private IamAccount testAccount;
  private Optional<IamLabel> statusLabel;

  @Before
  public void resetTestAccount() {

    testAccount = IamAccount.newAccount();
    testAccount.setUuid(USER_UUID);
    testAccount.setUsername(USER_USERNAME);
    testAccount.setActive(true);
    testAccount.getUserInfo().setGivenName("Test");
    testAccount.getUserInfo().setFamilyName("Test");
    testAccount.getUserInfo().setEmail("test.lifecycle.account@cern.ch");
    testAccount.setEndTime(null);
    testAccount.getLabels().clear();
    accountService.createAccount(testAccount);
    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(testAccount.isActive(), is(true));
    assertThat(statusLabel.isPresent(), is(false));
  }

  @After
  public void deleteAccount() {

    accountService.deleteAccount(testAccount);
  }

  @Test
  public void testUserIsNotPendingSuspensionWhenEndTimeIsToday() {

    accountService.setAccountEndTime(testAccount, Date.from(ONE_MINUTE_AGO));
    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);

    assertThat(testAccount.isActive(), is(true));
    assertThat(statusLabel.isPresent(), is(false));
  }

  @Test
  public void testSuspensionGracePeriodWorks() {

    accountService.setAccountEndTime(testAccount, Date.from(FOUR_DAYS_AGO));
    Date lastUpdateTime = testAccount.getLastUpdateTime();

    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);

    assertThat(testAccount.isActive(), is(true));
    assertThat(testAccount.getLastUpdateTime().compareTo(lastUpdateTime) > 0, is(true));
    lastUpdateTime = testAccount.getLastUpdateTime();
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(),
        is(ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_SUSPENSION.name()));

    handler.handleExpiredAccounts();

    testAccount = accountService.findByUuid(USER_UUID)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    assertThat(testAccount.isActive(), is(true));
    assertThat(testAccount.getLastUpdateTime().compareTo(lastUpdateTime) == 0, is(true));
  }

  @Test
  public void testRemovalGracePeriodWorks() {

    accountService.setAccountEndTime(testAccount, Date.from(EIGHT_DAYS_AGO));
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
  public void testAccountRemovalWorks() {

    accountService.setAccountEndTime(testAccount, Date.from(THIRTY_ONE_DAYS_AGO));

    handler.handleExpiredAccounts();

    assertThat(accountService.findByUuid(USER_UUID).isEmpty(), is(true));
  }

  @Test
  public void testNoAccountsRemoved() {

    long accountBefore = repo.count();

    handler.handleExpiredAccounts();

    long accountAfter = repo.count();

    assertThat(accountBefore, is(accountAfter));
  }


}
