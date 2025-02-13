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
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_TIMESTAMP;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.Date;
import java.util.Optional;
import java.util.Random;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    CernAccountLifecycleTests.TestConfig.class})
@TestPropertySource(properties = {
// @formatter:off
        "lifecycle.account.expiredAccountPolicy.suspensionGracePeriodDays=0",
        "lifecycle.account.expiredAccountPolicy.removalGracePeriodDays=30",
        "cern.task.pageSize=5"
    // @formatter:on
})
@ActiveProfiles(value = {"h2-test", "cern"})
public class CernAccountLifecycleTests extends TestSupport implements LifecycleTestSupport {

  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    Clock mockClock() {
      return Clock.fixed(NOW, ZoneId.systemDefault());
    }

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
  Clock clock;

  IamAccount cernUser;

  @Before
  public void init() {

    cernUser = IamAccount.newAccount();
    cernUser.setUsername(CERN_USER);
    cernUser.setUuid(CERN_USER_UUID);
    cernUser.setActive(true);
    cernUser.setEndTime(Date.from(NOW.plus(365, ChronoUnit.DAYS)));
    cernUser.getUserInfo().setEmail(CERN_USER + "@example");
    cernUser.getUserInfo().setGivenName("cern");
    cernUser.getUserInfo().setFamilyName("user");
    cernUser.getUserInfo().setEmailVerified(true);
    service.createAccount(cernUser);
    service.addLabel(cernUser, cernPersonIdLabel(CERN_PERSON_ID));
  }

  @After
  public void teardown() {
    reset(hrDb);
    service.deleteAccount(cernUser);
  }

  private IamAccount loadAccount(String username) {
    return repo.findByUuid(username).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
  }

  @Test
  public void testUserSuspensionWorksAfterCernHrEndTimeUpdate() {

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(expiredVoPerson(CERN_PERSON_ID)));

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

    Optional<IamLabel> cernTimestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(cernTimestampLabel.isPresent(), is(false));

    expiredAccountsHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(false));

    cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    cernMessageLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(SYNCHRONIZED_MESSAGE));

    cernTimestampLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(cernTimestampLabel.isPresent(), is(false));

    Optional<IamLabel> iamStatusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);
    assertThat(iamStatusLabel.isPresent(), is(true));
    assertThat(iamStatusLabel.get().getValue(), is(PENDING_REMOVAL.name()));

  }

  @Test
  public void testUserRemovalWorksAfterCernHrEndTimeUpdate() {

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(removedVoPerson(CERN_PERSON_ID)));

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

    Optional<IamLabel> cernTimestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(cernTimestampLabel.isPresent(), is(false));

    expiredAccountsHandler.run();

    assertThat(repo.findByUuid(CERN_USER_UUID).isEmpty(), is(true));
  }

  @Test
  public void testLifecycleWorksForValidAccounts() {

    VOPersonDTO voPerson = voPerson(CERN_PERSON_ID);
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

    Optional<IamLabel> cernTimestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(cernTimestampLabel.isPresent(), is(false));
  }

  @Test
  public void testLifecycleWorksForAccountsWithOneValidParticipationAndOneExpired() {

    VOPersonDTO voPerson = voPerson(CERN_PERSON_ID, getTestAccount(),
        Sets.newHashSet(getLimitedParticipation("test"), getExpiredParticipation("test", 20)));

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

    Optional<IamLabel> cernTimestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(cernTimestampLabel.isPresent(), is(false));
  }

  @Test
  public void testLifecycleWorksForAccountsWithOneUnlimitedParticipationAndOneExpired() {

    VOPersonDTO voPerson = voPerson(CERN_PERSON_ID, getTestAccount(),
        Sets.newHashSet(getUnlimitedParticipation("test"), getExpiredParticipation("test", 20)));

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

    Optional<IamLabel> cernTimestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(cernTimestampLabel.isPresent(), is(false));
  }


  @Test
  public void testLifecycleWhenVOPersonEndDateIsNull() {

    VOPersonDTO voPerson = voPerson(CERN_PERSON_ID, null);
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

    Optional<IamLabel> cernTimestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(cernTimestampLabel.isPresent(), is(false));
  }

  @Test
  public void testRestoreLifecycleWorks() {

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(voPerson(CERN_PERSON_ID)));

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
    Optional<IamLabel> cernTimestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    Optional<IamLabel> cernMessageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    Optional<IamLabel> iamStatusLabel = testAccount.getLabelByName(LIFECYCLE_STATUS_LABEL);

    assertThat(cernStatusLabel.isPresent(), is(true));
    assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

    assertThat(cernMessageLabel.isPresent(), is(true));
    assertThat(cernMessageLabel.get().getValue(), is(format(SYNCHRONIZED_MESSAGE)));

    assertThat(cernTimestampLabel.isPresent(), is(false));
    assertThat(iamStatusLabel.isPresent(), is(false));
  }

  @Test
  public void testApiErrorIsHandled() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenThrow(new CernHrDbApiError("API is unreachable"));

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.ERROR.name()));

    assertThat(timestampLabel.isPresent(), is(false));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(HR_DB_API_ERROR));

  }

  @Test
  public void testApiReturnsNullVoPersonIsHandled() {

    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(Optional.empty());

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
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
    assertThat(messageLabel.get().getValue(), is(format(NO_PERSON_FOUND_MESSAGE, CERN_PERSON_ID)));

  }

  @Test
  public void testNullEndTimeAndNoVoPersonFoundOnHR() {

    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(Optional.empty());

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    testAccount.setEndTime(null);
    repo.save(testAccount);

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
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
    assertThat(messageLabel.get().getValue(), is(format(NO_PERSON_FOUND_MESSAGE, CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    statusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));

  }

  @Test
  public void testVoPersonWithNoValidParticipationIsHandled() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenReturn(Optional.of(noParticipationsVoPerson(CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
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

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    statusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.EXPIRED.name()));
  }

  @Test
  public void testNoEmailVoPersonIsReturned() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenReturn(Optional.of(noEmailVoPerson(CERN_PERSON_ID)));

    cernHrLifecycleHandler.run();

    IamAccount testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    assertNotNull(testAccount.getUserInfo().getEmail());
  }

  @Test
  public void testLifecycleNotRestoreAccountsSuspendedByAdmins() {

    when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID))
      .thenReturn(Optional.of(voPerson(CERN_PERSON_ID)));

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

    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    assertThat(timestampLabel.isPresent(), is(false));
  }

  @Test
  public void testIgnoreAccount() {

    IamAccount testAccount = loadAccount(CERN_USER_UUID);
    assertThat(testAccount.isActive(), is(true));

    service.addLabel(testAccount, cernIgnoreLabel());

    cernHrLifecycleHandler.run();

    testAccount = loadAccount(CERN_USER_UUID);

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernStatus.IGNORED.name()));

    assertThat(timestampLabel.isPresent(), is(false));

    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(IGNORE_MESSAGE));
  }

  @Test
  public void testPaginationWorks() {

    when(hrDb.getHrDbPersonRecord(anyString()))
      .thenReturn(Optional.of(voPerson(String.valueOf(new Random().nextLong() % 100L))));

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
      Optional<IamLabel> timestampLabel =
          account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);

      assertThat(statusLabel.isPresent(), is(true));
      assertThat(statusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

      assertThat(timestampLabel.isPresent(), is(false));
    }
  }

  @Test
  public void testEmailNotSynchronizedIfSkipEmailSyncIsPresent() {

    VOPersonDTO voPerson = voPerson(CERN_PERSON_ID);

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

}
