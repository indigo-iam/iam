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
package it.infn.mw.iam.test.lifecycle.cern;

import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.NO_PARTICIPATION_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.NO_PERSON_FOUND_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_STATUS;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_TIMESTAMP;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    ClockConfig.class, CernAccountLifecycleDisableUserTests.TestConfig.class})
@TestPropertySource(properties = {
// @formatter:off
  "cern.task.pageSize=5",
  // @formatter:on
})
@Transactional
@ActiveProfiles(value = {"h2-test", "cern"})
class CernAccountLifecycleDisableUserTests implements LifecycleTestSupport {

  static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";

  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    CernHrDBApiService hrDb() {
      return mock(CernHrDBApiService.class);
    }
  }

  @Autowired
  IamAccountRepository repo;

  @Autowired
  IamAccountService service;

  @Autowired
  CernHrLifecycleHandler cernHrLifecycleHandler;

  @Autowired
  ExpiredAccountsHandler expiredAccountsHandler;

  @Autowired
  CernHrDBApiService hrDb;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  IamAccount cernUser;

  private IamAccount getCernUser() {
    IamAccount a = IamAccount.newAccount();
    a.setUsername(CERN_USER);
    a.setUuid(CERN_USER_UUID);
    a.setActive(true);
    a.setEndTime(Date.from(clock.daysAfter(165)));
    a.getUserInfo().setEmail(CERN_USER + "@example");
    a.getUserInfo().setGivenName("cern");
    a.getUserInfo().setFamilyName("user");
    a.getUserInfo().setEmailVerified(true);
    return a;
  }

  @BeforeEach
  void init() {
    cernUser = service.createAccount(getCernUser());
    service.addLabel(cernUser, cernPersonIdLabel(CERN_PERSON_ID));
  }

  @AfterEach
  void teardown() {
    reset(hrDb);
  }

  private IamAccount loadAccount(String username) {
    return repo.findByUuid(username).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
  }

  @Test
  void testCernPersonIdNotFoundMeansUserEndTimeIsResetToCurrentDate() {

    Date currentEndTime = cernUser.getEndTime();
    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(Optional.empty());

    cernHrLifecycleHandler.run();

    cernUser = loadAccount(CERN_USER_UUID);

    assertThat(cernUser.isActive(), is(true));
    assertThat(cernUser.getEndTime().compareTo(currentEndTime) < 0, is(true));

    Optional<IamLabel> statusLabel =
        cernUser.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> timestampLabel =
        cernUser.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    Optional<IamLabel> messageLabel =
        cernUser.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));

    assertThat(timestampLabel.isPresent(), is(false));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(format(NO_PERSON_FOUND_MESSAGE, CERN_PERSON_ID)));

    clock.advance(Duration.ofHours(36));

    expiredAccountsHandler.run();

    cernUser = loadAccount(CERN_USER_UUID);

    assertThat(cernUser.isActive(), is(true));

    Optional<IamLabel> lifecycleStatusLabel =
        cernUser.getLabelByName(ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL);

    assertThat(lifecycleStatusLabel.isPresent(), is(true));
    assertThat(lifecycleStatusLabel.get().getValue(),
        is(AccountLifecycleStatus.PENDING_SUSPENSION.name()));
  }

  @Test
  void testNoParticipationIsFoundMeansUserEndTimeIsResetToCurrentDate() {

    Date currentEndTime = cernUser.getEndTime();

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenReturn(Optional.of(noParticipationsVoPerson(CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    assertThat(testAccount.getEndTime().compareTo(currentEndTime) < 0, is(true));

    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));

    assertThat(timestampLabel.isPresent(), is(false));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(format(NO_PARTICIPATION_MESSAGE, "test")));

    clock.advance(Duration.ofHours(36));

    expiredAccountsHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> lifecycleStatusLabel =
        testAccount.getLabelByName(ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL);

    assertThat(lifecycleStatusLabel.isPresent(), is(true));
    assertThat(lifecycleStatusLabel.get().getValue(),
        is(AccountLifecycleStatus.PENDING_SUSPENSION.name()));

  }

  @Test
  void testEndTimeIsNotSynchronizedIfSkipLabelIsPresent() {

    VOPersonDTO voPerson = voPerson(clock, CERN_PERSON_ID);

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));
    Date endTime = testAccount.getEndTime();
    assertThat(endTime, not(is(voPerson.getParticipations().iterator().next().getEndDate())));

    service.addLabel(testAccount, skipEndDateSyncLabel());
    repo.save(testAccount);

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));
    endTime = testAccount.getEndTime();
    assertThat(endTime, not(is(voPerson.getParticipations().iterator().next().getEndDate())));

  }

}
