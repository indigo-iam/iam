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
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_TIMESTAMP_LABEL;
import static java.lang.String.valueOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.time.Clock;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
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
        "lifecycle.account.expiredAccountPolicy.removalGracePeriodDays=30"})
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
  private ExpiredAccountsHandler handler;

  @Test
  public void testSuspensionGracePeriodWorks() {
    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));

    testAccount.setEndTime(Date.from(FOUR_DAYS_AGO));
    repo.save(testAccount);

    handler.handleExpiredAccounts();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> timestampLabel = testAccount.getLabelByName(LIFECYCLE_TIMESTAMP_LABEL);

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(NOW.toEpochMilli())));

    Optional<IamLabel> statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(),
        is(ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_SUSPENSION.name()));
  }

  @Test
  public void testRemovalGracePeriodWorks() {
    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));
    testAccount.setEndTime(Date.from(EIGHT_DAYS_AGO));
    repo.save(testAccount);

    handler.handleExpiredAccounts();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));

    Optional<IamLabel> timestampLabel = testAccount.getLabelByName(LIFECYCLE_TIMESTAMP_LABEL);

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(NOW.toEpochMilli())));

    Optional<IamLabel> statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(),
        is(ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_REMOVAL.name()));
  }

  @Test
  public void testAccountRemovalWorks() {
    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    testAccount.setEndTime(Date.from(THIRTY_ONE_DAYS_AGO));

    repo.save(testAccount);

    handler.handleExpiredAccounts();

    Optional<IamAccount> account = repo.findByUuid(TEST_USER_UUID);;

    assertThat(account.isPresent(), is(false));
  }

  @Test
  public void testNoAccountsRemoved() {

    long accountBefore = repo.count();

    handler.handleExpiredAccounts();

    long accountAfter = repo.count();

    assertThat(accountBefore, is(accountAfter));
  }

  @Test
  public void testMultiplePagesOfAccountsRemoved() {

    long accountBefore = repo.count();

    Page<IamAccount> accountsPage = repo.findAll(PageRequest.of(0, 20));

    long touchedAccounts = 0;
    
    if (accountsPage.hasContent()) {
      for (IamAccount a: accountsPage.getContent()) {
        a.setEndTime(Date.from(THIRTY_ONE_DAYS_AGO));
        repo.save(a);
        touchedAccounts++;
      }
    }

    assertThat(touchedAccounts, is(20L));
    
    handler.handleExpiredAccounts();

    long accountAfter = repo.count();

    assertThat(accountAfter, is(accountBefore - 20));
  }



}
