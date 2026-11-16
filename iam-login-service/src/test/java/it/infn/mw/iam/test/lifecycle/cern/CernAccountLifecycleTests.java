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

import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus.PENDING_REMOVAL;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus.SUSPENDED;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.HR_DB_API_ERROR;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.IGNORE_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.NO_PARTICIPATION_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.NO_PERSON_FOUND_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.SYNCHRONIZED_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_STATUS;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernAccountLifecycleTask;
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

@Transactional
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    ClockConfig.class, CernAccountLifecycleTests.TestConfig.class})
@TestPropertySource(properties = {"spring.profiles.include=${spring.profiles.active:h2-test},cern",
    "lifecycle.account.expiredAccountPolicy.suspensionGracePeriodDays=0",
    "lifecycle.account.expiredAccountPolicy.removalGracePeriodDays=30",
    "lifecycle.account.expiredAccountsTask.enabled=true", "cern.task.pageSize=5"})
class CernAccountLifecycleTests implements LifecycleTestSupport {

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
  CernAccountLifecycleTask cernLifecycleTask;

  @Autowired
  CernHrDBApiService hrDb;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  IamAccount cernUser;

  @BeforeEach
  void init() {

    cernUser = IamAccount.newAccount();
    cernUser.setUsername(CERN_USER);
    cernUser.setUuid(CERN_USER_UUID);
    cernUser.setActive(true);
    cernUser.setEndTime(Date.from(clock.daysAfter(365).truncatedTo(ChronoUnit.SECONDS)));
    cernUser.getUserInfo().setEmail(CERN_USER + "@example");
    cernUser.getUserInfo().setGivenName("cern");
    cernUser.getUserInfo().setFamilyName("user");
    cernUser.getUserInfo().setEmailVerified(true);
    service.createAccount(cernUser);
    service.addLabel(cernUser, cernPersonIdLabel(CERN_PERSON_ID));
  }

  @AfterEach
  void teardown() {
    reset(hrDb);
    service.deleteAccount(cernUser);
  }

  private IamAccount loadAccount(String username) {
    return repo.findByUuid(username).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
  }

  @Test
  void testUserSuspensionWorksAfterCernHrEndTimeUpdate() {

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(expiredVoPerson(clock, CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> cernStatusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));

    expiredAccountsHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(false));

    cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    cernMessageLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));

    Optional<IamLabel> iamStatusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(iamStatusLabel.isPresent(), is(true));
    assertThat(iamStatusLabel.get().getValue(), is(PENDING_REMOVAL.name()));

  }

  @Test
  void testUserRemovalWorksAfterCernHrEndTimeUpdate() {

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(removedVoPerson(clock, CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> cernStatusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));

    expiredAccountsHandler.run();

    assertThat(repo.findByUuid(CERN_USER_UUID).isEmpty(), is(true));
  }

  @Test
  void testLifecycleWorksForValidAccounts() {

    VOPersonDTO voPerson = voPerson(clock, CERN_PERSON_ID);
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.getUserInfo().getGivenName(), is(voPerson.getFirstName()));
    assertThat(testAccount.getUserInfo().getFamilyName(), is(voPerson.getName()));
    assertThat(testAccount.getUserInfo().getEmail(), is(voPerson.getEmail()));
    assertThat(testAccount.getEndTime(),
        is(voPerson.getParticipations().iterator().next().getEndDate()));

    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> cernStatusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));

  }

  @Test
  void testLifecycleWorksForAccountsWithOneValidParticipationAndOneExpired() {

    VOPersonDTO voPerson = voPerson(CERN_PERSON_ID, getTestAccount(), Sets.newHashSet(
        getLimitedParticipation(clock, "test"), getExpiredParticipation(clock, "test", 20)));

    Comparator<ParticipationDTO> comparator = Comparator.comparing(ParticipationDTO::getEndDate);

    ParticipationDTO highestParticipation =
        voPerson.getParticipations().stream().max(comparator).get();
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.getUserInfo().getGivenName(), is(voPerson.getFirstName()));
    assertThat(testAccount.getUserInfo().getFamilyName(), is(voPerson.getName()));
    assertThat(testAccount.getUserInfo().getEmail(), is(voPerson.getEmail()));
    assertThat(testAccount.getEndTime(), is(highestParticipation.getEndDate()));

    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> cernStatusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));
  }

  @Test
  void testLifecycleWorksForAccountsWithOneUnlimitedParticipationAndOneExpired() {

    VOPersonDTO voPerson = voPerson(CERN_PERSON_ID, getTestAccount(), Sets.newHashSet(
        getUnlimitedParticipation(clock, "test"), getExpiredParticipation(clock, "test", 20)));

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.getUserInfo().getGivenName(), is(voPerson.getFirstName()));
    assertThat(testAccount.getUserInfo().getFamilyName(), is(voPerson.getName()));
    assertThat(testAccount.getUserInfo().getEmail(), is(voPerson.getEmail()));
    assertThat(testAccount.getEndTime(), is(nullValue()));

    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> cernStatusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));
  }


  @Test
  void testLifecycleWhenVOPersonEndDateIsNull() {

    VOPersonDTO voPerson = voPerson(clock, CERN_PERSON_ID, null);
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.getUserInfo().getGivenName(), is(voPerson.getFirstName()));
    assertThat(testAccount.getUserInfo().getFamilyName(), is(voPerson.getName()));
    assertThat(testAccount.getUserInfo().getEmail(), is(voPerson.getEmail()));
    assertThat(testAccount.getEndTime(), nullValue());

    assertThat(testAccount.isActive(), is(true));

    Optional<IamLabel> cernStatusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));
  }

  @Test
  void testRestoreLifecycleWorks() {

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(voPerson(clock, CERN_PERSON_ID)));

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));

    // suspend testAccount
    service.disableAccount(testAccount);
    service.addLabel(testAccount, statusLabel(SUSPENDED));

    // run CERN account life-cycle handler
    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> cernStatusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    Optional<IamLabel> iamStatusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);

    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(format(SYNCHRONIZED_MESSAGE)));

    assertThat(iamStatusLabel.isPresent(), is(false));
  }

  @Test
  void testRestoreRemovesLifecycleStatusWhenEndTimeIsUnchanged() {
    VOPersonDTO person = voPerson(clock, CERN_PERSON_ID);
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(person));

    IamAccount account = loadAccount(CERN_USER_UUID);
    // First synchronize the end time while the account is active.
    cernHrLifecycleHandler.run();
    account = loadAccount(CERN_USER_UUID);
    Date synchronizedEndTime = account.getEndTime();

    service.disableAccount(account);
    service.addLabel(account, statusLabel(SUSPENDED));

    // The next HR sync restores the account without changing its end time.
    cernHrLifecycleHandler.run();
    account = loadAccount(CERN_USER_UUID);

    assertThat(account.isActive(), is(true));
    assertThat(account.getEndTime(), is(synchronizedEndTime));
    assertThat(account.getLabelByName(LIFECYCLE_STATUS_LABEL).isPresent(), is(false));
  }

  @Test
  void coordinatedCycleRenewsMembershipBeforeExpiration() {
    service.setAccountEndTime(cernUser,
        Date.from(clock.instant().minus(40, java.time.temporal.ChronoUnit.DAYS)));
    VOPersonDTO person = voPerson(clock, CERN_PERSON_ID);
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(person));

    cernLifecycleTask.run();

    IamAccount account = loadAccount(CERN_USER_UUID);
    assertTrue(account.isActive());
    assertTrue(account.getEndTime().after(Date.from(clock.instant())));
  }

  @Test
  void coordinatedCycleSuspendsExpiredAccountWhenHrPersonIsAbsent() {
    service.setAccountEndTime(cernUser,
        Date.from(clock.instant().minus(1, java.time.temporal.ChronoUnit.DAYS)));
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.empty());

    cernLifecycleTask.run();

    assertThat(loadAccount(CERN_USER_UUID).isActive(), is(false));
  }

  @Test
  void coordinatedCycleDefersRemovalWhenHrRequestFails() {
    service.setAccountEndTime(cernUser,
        Date.from(clock.instant().minus(40, java.time.temporal.ChronoUnit.DAYS)));
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenThrow(new CernHrDbApiError("API is unreachable"));

    cernLifecycleTask.run();

    assertTrue(loadAccount(CERN_USER_UUID).isActive());
  }

  @Test
  void testApiErrorIsHandled() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenThrow(new CernHrDbApiError("API is unreachable"));

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.ERROR.name()));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(HR_DB_API_ERROR));

  }

  @Test
  void testApiReturnsNullVoPersonIsHandled() {

    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(Optional.empty());

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(format(NO_PERSON_FOUND_MESSAGE, CERN_PERSON_ID)));

  }

  @Test
  void testNullEndTimeAndNoVoPersonFoundOnHR() {

    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(Optional.empty());

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    testAccount.setEndTime(null);
    repo.save(testAccount);

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(format(NO_PERSON_FOUND_MESSAGE, CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    statusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));

  }

  @Test
  void testVoPersonWithNoValidParticipationIsHandled() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenReturn(Optional.of(noParticipationsVoPerson(CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(format(NO_PARTICIPATION_MESSAGE, "test")));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    statusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));
  }

  @Test
  @Transactional(propagation = Propagation.NOT_SUPPORTED)
  void duplicateHrEmailStillCommitsMembershipRenewal() {
    IamAccount owner = getTestAccount();
    owner.setUsername("cern-email-owner");
    owner = service.createAccount(owner);
    try {
      assertHrRenewalCommitsWithEmail(owner.getUserInfo().getEmail());
    } finally {
      service.deleteAccount(owner);
    }
  }

  @Test
  @Transactional(propagation = Propagation.NOT_SUPPORTED)
  void missingHrEmailStillCommitsMembershipRenewal() {
    assertHrRenewalCommitsWithEmail(null);
  }

  private void assertHrRenewalCommitsWithEmail(String hrEmail) {
    Date endTime =
        Date.from(clock.daysAfter(90).truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
    VOPersonDTO person = voPerson(clock, CERN_PERSON_ID, endTime);
    person.setEmail(hrEmail);
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(person));

    cernHrLifecycleHandler.handleAccount(CERN_PERSON_ID, "test", cernUser);

    IamAccount renewed = loadAccount(CERN_USER_UUID);
    assertThat(renewed.getEndTime(), is(endTime));
    assertThat(renewed.getUserInfo().getEmail(), is(CERN_USER + "@example"));
  }

  @Test
  void testNoEmailVoPersonIsReturned() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenReturn(Optional.of(noEmailVoPerson(clock, CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    assertNotNull(testAccount.getUserInfo().getEmail());
  }

  @Test
  void testLifecycleNotRestoreAccountsSuspendedByAdmins() {

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(voPerson(clock, CERN_PERSON_ID)));

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));
    service.disableAccount(testAccount);

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(false));

    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));
  }

  @Test
  void testIgnoreAccount() {

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    service.addLabel(testAccount, cernIgnoreLabel());

    cernHrLifecycleHandler.run();
    verifyNoInteractions(hrDb);

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.IGNORED.name()));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(IGNORE_MESSAGE));
  }

  @Test
  void testIgnoreLabelAddedDuringSuccessfulHrRequest() {
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenAnswer(invocation -> {
      service.addLabel(loadAccount(CERN_USER_UUID), cernIgnoreLabel());
      return Optional.of(expiredVoPerson(clock, CERN_PERSON_ID));
    });

    assertIgnoredAfterHrRequest();
  }

  @Test
  void testIgnoreLabelAddedDuringMissingPersonHrRequest() {
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenAnswer(invocation -> {
      service.addLabel(loadAccount(CERN_USER_UUID), cernIgnoreLabel());
      return Optional.empty();
    });

    assertIgnoredAfterHrRequest();
  }

  @Test
  void testIgnoreLabelAddedDuringFailedHrRequest() {
    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenAnswer(invocation -> {
      service.addLabel(loadAccount(CERN_USER_UUID), cernIgnoreLabel());
      throw new CernHrDbApiError("API is unreachable");
    });

    assertIgnoredAfterHrRequest();
  }

  private void assertIgnoredAfterHrRequest() {
    IamAccount before = loadAccount(CERN_USER_UUID);
    Date endTime = before.getEndTime();
    String email = before.getUserInfo().getEmail();
    String givenName = before.getUserInfo().getGivenName();
    String familyName = before.getUserInfo().getFamilyName();

    cernHrLifecycleHandler.handleAccount(CERN_PERSON_ID, "test", before);

    verify(hrDb).getHrDbPersonRecord(CERN_PERSON_ID);
    IamAccount account = loadAccount(CERN_USER_UUID);
    assertThat(account.isActive(), is(true));
    assertThat(account.getEndTime(), is(endTime));
    assertThat(account.getUserInfo().getEmail(), is(email));
    assertThat(account.getUserInfo().getGivenName(), is(givenName));
    assertThat(account.getUserInfo().getFamilyName(), is(familyName));
    assertThat(account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS)
      .orElseThrow(AssertionError::new)
      .getValue(), is(CernStatus.IGNORED.name()));
    assertThat(account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE)
      .orElseThrow(AssertionError::new)
      .getValue(), is(IGNORE_MESSAGE));
  }

  @Test
  void synchronizesEveryAccountExactlyOnceAcrossMultiplePages() {
    // cern.task.pageSize=5; 12 accounts force three pages.
    List<String> personIds = new ArrayList<>();
    personIds.add(CERN_PERSON_ID);

    for (int i = 0; i < 11; i++) {
      String uuid = UUID.randomUUID().toString();
      String personId = String.valueOf(100000 + i);
      IamAccount account = IamAccount.newAccount();
      account.setUuid(uuid);
      account.setUsername("cern-pagination-" + uuid);
      account.setActive(true);
      account.setEndTime(Date.from(clock.daysAfter(365).truncatedTo(ChronoUnit.SECONDS)));
      account.getUserInfo().setEmail("cern-pagination-" + uuid + "@example.org");
      account.getUserInfo().setGivenName("Pagination");
      account.getUserInfo().setFamilyName("Test");
      account.getUserInfo().setEmailVerified(true);
      service.createAccount(account);
      service.addLabel(account, cernPersonIdLabel(personId));
      personIds.add(personId);
    }

    // Missing HR records update the CERN status without changing the selection label.
    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(Optional.empty());

    assertThat(cernHrLifecycleHandler.synchronizeAccounts().isEmpty(), is(true));

    for (String personId : personIds) {
      verify(hrDb, times(1)).getHrDbPersonRecord(personId);
    }
  }

  @Test
  void testPaginationWorks() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenReturn(Optional.of(voPerson(clock, String.valueOf(new Random().nextLong() % 100L))));

    Pageable pageRequest = PageRequest.of(0, 10, Direction.ASC, "username");
    Page<IamAccount> accountPage = repo.findAll(pageRequest);

    for (IamAccount account : accountPage.getContent()) {
      service.addLabel(account, cernPersonIdLabel(UUID.randomUUID().toString()));
    }

    cernHrLifecycleHandler.run();

    accountPage = repo.findAll(pageRequest);

    for (IamAccount account : accountPage.getContent()) {

      assertThat(account.isActive(), is(true));
      Optional<IamLabel> statusLabel =
          account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);

      assertThat(statusLabel.isPresent(), is(true));
      assertThat(statusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));
    }
  }

  @Test
  void testEmailNotSynchronizedIfSkipEmailSyncIsPresent() {

    VOPersonDTO voPerson = voPerson(clock, CERN_PERSON_ID);

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    final String preSyncEmail = testAccount.getUserInfo().getEmail();

    assertThat(voPerson.getEmail().equals(preSyncEmail), is(false));
    assertThat(testAccount.isActive(), is(true));

    service.addLabel(testAccount, skipEmailSyncLabel());
    repo.save(testAccount);

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.getUserInfo().getGivenName(), is(voPerson.getFirstName()));
    assertThat(testAccount.getUserInfo().getFamilyName(), is(voPerson.getName()));
    assertThat(testAccount.getUserInfo().getEmail(), is(preSyncEmail));
  }

  @Test
  void isValidShouldReturnTrueWhenEndTimeIsNull() {

    Date now = Date.from(clock.instant());
    IamAccount account = IamAccount.newAccount();
    account.setEndTime(null);
    assertTrue(account.isValid(now));
  }
}
