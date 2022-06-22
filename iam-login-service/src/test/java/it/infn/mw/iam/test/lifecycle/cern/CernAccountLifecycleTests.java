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

import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.HR_DB_API_ERROR;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.IGNORE_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_ACTION;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_STATUS;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_TIMESTAMP;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.Action.DISABLE_ACCOUNT;
import static java.lang.String.valueOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.ZoneId;
import java.util.Optional;
import java.util.UUID;

import org.junit.After;
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

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler;
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
  CernHrLifecycleHandler handler;

  @Autowired
  CernHrDBApiService hrDb;

  @Autowired
  Clock clock;
  
  @After
  public void teardown() {
    reset(hrDb);
  }

  @Test
  public void testSuspendLifecycleWorks() {

    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(false);

    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));

    service.setLabel(testAccount, cernPersonIdLabel());
    repo.save(testAccount);

    handler.run();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> actionLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.OK.name()));

    assertThat(actionLabel.isPresent(), is(true));
    assertThat(actionLabel.get().getValue(),
        is(CernHrLifecycleHandler.Action.DISABLE_ACCOUNT.name()));

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
  }

  @Test
  public void testNoActionLifecycleWorksForValidAccounts() {
    VOPersonDTO voPerson = voPerson("988211");
    
    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(true);
    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(voPerson);

    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));

    service.setLabel(testAccount, cernPersonIdLabel());
    repo.save(testAccount);

    handler.run();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.getUserInfo().getGivenName(), is(voPerson.getFirstName()));
    assertThat(testAccount.getUserInfo().getFamilyName(), is(voPerson.getName()));
    assertThat(testAccount.getUserInfo().getEmail(), is(voPerson.getEmail()));
    
    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> actionLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.OK.name()));

    assertThat(actionLabel.isPresent(), is(true));
    assertThat(actionLabel.get().getValue(), is(CernHrLifecycleHandler.Action.NO_ACTION.name()));

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
  }
  
  @Test
  public void testNoActionLifecycleWorksForInValidAccounts() {

    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(false);

    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));

    testAccount.setActive(false);
    service.setLabel(testAccount, cernPersonIdLabel());
    
    handler.run();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> actionLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.OK.name()));

    assertThat(actionLabel.isPresent(), is(true));
    assertThat(actionLabel.get().getValue(), is(CernHrLifecycleHandler.Action.NO_ACTION.name()));

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
  }

  @Test
  public void testRestoreLifecycleWorks() {

    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(true);
    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(voPerson("988211"));
    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));

    testAccount.setActive(false);

    service.setLabel(testAccount, cernPersonIdLabel());
    service.setLabel(testAccount, actionLabel(DISABLE_ACCOUNT));

    handler.run();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> actionLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.OK.name()));

    assertThat(actionLabel.isPresent(), is(true));
    assertThat(actionLabel.get().getValue(),
        is(CernHrLifecycleHandler.Action.RESTORE_ACCOUNT.name()));

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
  }
  
  @Test
  public void testApiErrorIsHandled() {
    when(hrDb.hasValidExperimentParticipation(anyString())).thenThrow(new CernHrDbApiError("API is unreachable"));
    
    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    service.setLabel(testAccount, cernPersonIdLabel());
    
    handler.run();
    
    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    
    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> actionLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);

    assertThat(actionLabel.isPresent(), is(false));
    
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.ERROR.name()));
    
    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
    
    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(HR_DB_API_ERROR));
    
  }
  
  @Test
  public void testRestoreLifecycleDoesNotTouchSuspendedAccount() {

    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(true);
    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(voPerson("988211"));
    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));

    testAccount.setActive(false);

    service.setLabel(testAccount, cernPersonIdLabel());

    handler.run();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(false));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> actionLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);

    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.OK.name()));

    assertThat(actionLabel.isPresent(), is(true));
    assertThat(actionLabel.get().getValue(),
        is(CernHrLifecycleHandler.Action.NO_ACTION.name()));

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
  }
  
  @Test
  public void testIgnoreAccount() {
    
    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(false);
    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    
    assertThat(testAccount.isActive(), is(true));
    
    service.setLabel(testAccount, cernPersonIdLabel());
    service.setLabel(testAccount, cernIgnoreLabel());
    
    handler.run();
    
    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.isActive(), is(true));
    Optional<IamLabel> statusLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
    Optional<IamLabel> actionLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
    Optional<IamLabel> timestampLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);
    Optional<IamLabel> messageLabel =
        testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_MESSAGE);
    
    assertThat(statusLabel.isPresent(), is(true));
    assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.OK.name()));

    assertThat(actionLabel.isPresent(), is(true));
    assertThat(actionLabel.get().getValue(),
        is(CernHrLifecycleHandler.Action.NO_ACTION.name()));

    assertThat(timestampLabel.isPresent(), is(true));
    assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
    
    assertThat(messageLabel.isPresent(), is(true));
    assertThat(messageLabel.get().getValue(), is(IGNORE_MESSAGE));
  }

  @Test
  public void testPaginationWorks() {
    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(false);

    Pageable pageRequest = PageRequest.of(0, 10, Direction.ASC, "username");
    Page<IamAccount> accountPage = repo.findAll(pageRequest);

    for (IamAccount account : accountPage.getContent()) {
      service.setLabel(account, cernPersonIdLabel(UUID.randomUUID().toString()));
    }

    handler.run();

    accountPage = repo.findAll(pageRequest);

    for (IamAccount account : accountPage.getContent()) {
      
      assertThat(account.isActive(), is(false));
      Optional<IamLabel> statusLabel =
          account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
      Optional<IamLabel> actionLabel =
          account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_ACTION);
      Optional<IamLabel> timestampLabel =
          account.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_TIMESTAMP);

      assertThat(statusLabel.isPresent(), is(true));
      assertThat(statusLabel.get().getValue(), is(CernHrLifecycleHandler.Status.OK.name()));

      assertThat(actionLabel.isPresent(), is(true));
      assertThat(actionLabel.get().getValue(),
          is(CernHrLifecycleHandler.Action.DISABLE_ACCOUNT.name()));

      assertThat(timestampLabel.isPresent(), is(true));
      assertThat(timestampLabel.get().getValue(), is(valueOf(clock.instant().toEpochMilli())));
      
      
    }
  }

  @Test
  public void testEmailNotSynchronizedIfSkipEmailSyncIsPresent() {

    VOPersonDTO voPerson = voPerson("988211");

    when(hrDb.hasValidExperimentParticipation(anyString())).thenReturn(true);
    when(hrDb.getHrDbPersonRecord(anyString())).thenReturn(voPerson);

    IamAccount testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    final String preSyncEmail = testAccount.getUserInfo().getEmail();

    assertThat(testAccount.isActive(), is(true));

    service.setLabel(testAccount, cernPersonIdLabel());
    service.setLabel(testAccount, skipEmailSyncLabel());
    repo.save(testAccount);

    handler.run();

    testAccount =
        repo.findByUuid(TEST_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    assertThat(testAccount.getUserInfo().getGivenName(), is(voPerson.getFirstName()));
    assertThat(testAccount.getUserInfo().getFamilyName(), is(voPerson.getName()));
    assertThat(testAccount.getUserInfo().getEmail(), is(preSyncEmail));
  }

}
