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

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.lifecycle.cern.LifecycleTestSupport;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class})
@TestPropertySource(
    properties = {"lifecycle.account.expiredAccountPolicy.removeExpiredAccounts=false"})
@Transactional
class AccountLifecycleNoRemovalExpiredAccountTests implements LifecycleTestSupport {

  static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";

  @Autowired
  IamAccountRepository repo;

  @Autowired
  ExpiredAccountsHandler handler;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  @Test
  void testSuspendedLabelWorks() {
    IamAccount testAccount =
        repo.findByUuid(TEST_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));
    testAccount.setEndTime(Date.from(clock.daysBefore(9)));
    repo.save(testAccount);
    Date lastUpdateTime = testAccount.getLastUpdateTime();

    handler.handleExpiredAccounts();

    testAccount =
        repo.findByUuid(TEST_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));
    assertThat(testAccount.getLastUpdateTime().compareTo(lastUpdateTime) > 0, is(true));
    lastUpdateTime = testAccount.getLastUpdateTime();

    handler.handleExpiredAccounts();

    testAccount =
        repo.findByUuid(TEST_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));
    assertThat(testAccount.getLastUpdateTime().compareTo(lastUpdateTime) == 0, is(true));

    Optional<IamLabel> statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(),
        is(ExpiredAccountsHandler.AccountLifecycleStatus.SUSPENDED.name()));
  }

  @Test
  void testNoRemovalWorks() {
    IamAccount testAccount =
        repo.findByUuid(TEST_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));
    testAccount.setEndTime(Date.from(clock.daysBefore(31)));
    repo.save(testAccount);

    handler.handleExpiredAccounts();

    testAccount =
        repo.findByUuid(TEST_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));

    Optional<IamLabel> statusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(),
        is(ExpiredAccountsHandler.AccountLifecycleStatus.SUSPENDED.name()));

    Optional<IamAccount> account = repo.findByUuid(TEST_UUID);
    assertThat(account.isPresent(), is(true));
  }

}
