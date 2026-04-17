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
package it.infn.mw.iam.test.api.account.find;

import static it.infn.mw.iam.api.account.find.FindAccountController.FIND_INACTIVE_SINCE_DAYS_RESOURCE;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.time.Duration;
import java.util.Date;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK,
    properties = {"lifecycle.account.inactive-accounts-report-enabled=true"})
@AutoConfigureMockMvc
@Transactional
@WithMockUser(username = "admin", roles = "ADMIN")
class FindInactiveSinceDaysIntegrationTests implements StructuredScopeTestSupportConstants {

  static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";

  @Autowired
  MockMvc mvc;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  MutableClock clock;

  @Autowired
  SecurityContextUtils context;

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
    Date recent = Date.from(clock.instant().minus(Duration.ofDays(1)));
    accountRepo.findAll().forEach(a -> {
      a.setLastLoginTime(recent);
      accountRepo.save(a);
    });
  }

  @Test
  @WithAnonymousUser
  void findingRequiresAuthenticatedUser() throws Exception {
    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE)).andExpect(UNAUTHORIZED);
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void findingRequiresAdminUser() throws Exception {
    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE)).andExpect(FORBIDDEN);
  }

  @Test
  void findInactiveSinceDaysWorks() throws Exception {
    IamAccount testAccount = accountRepo.findByUuid(TEST_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    testAccount.setLastLoginTime(Date.from(clock.instant().minus(Duration.ofDays(200))));
    accountRepo.save(testAccount);

    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE).param("days", "180"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(TEST_UUID)));
  }

  @Test
  void findInactiveSinceDaysExcludesActiveAccountsWorks() throws Exception {
    IamAccount testAccount = accountRepo.findByUuid(TEST_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    testAccount.setLastLoginTime(Date.from(clock.instant().minus(Duration.ofDays(30))));
    accountRepo.save(testAccount);

    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE).param("days", "180"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)));
  }

  @Test
  void findInactiveSinceDaysDefaultThresholdWorks() throws Exception {
    IamAccount testAccount = accountRepo.findByUuid(TEST_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    testAccount.setLastLoginTime(Date.from(clock.instant().minus(Duration.ofDays(181))));
    accountRepo.save(testAccount);

    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)));
  }

  @Test
  void findInactiveSinceDaysNeverLoggedInWorks() throws Exception {
    IamAccount testAccount = accountRepo.findByUuid(TEST_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    testAccount.setLastLoginTime(null);
    accountRepo.save(testAccount);

    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE).param("days", "90"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(TEST_UUID)));
  }

  @Test
  void findInactiveSinceDaysExcludesSuspendedWorks() throws Exception {
    IamAccount testAccount = accountRepo.findByUuid(TEST_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    testAccount.setLastLoginTime(Date.from(clock.instant().minus(Duration.ofDays(200))));
    testAccount.setActive(false);
    accountRepo.save(testAccount);

    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE).param("days", "180"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)));
  }

  @Test
  void findInactiveSinceDaysPaginationWorks() throws Exception {
    IamAccount account1 = accountRepo.findByUuid(TEST_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    account1.setLastLoginTime(Date.from(clock.instant().minus(Duration.ofDays(100))));
    accountRepo.save(account1);

    IamAccount account2 = accountRepo.findByUuid(TEST_100_USER_UUID)
        .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    account2.setLastLoginTime(Date.from(clock.instant().minus(Duration.ofDays(100))));
    accountRepo.save(account2);

    mvc.perform(get(FIND_INACTIVE_SINCE_DAYS_RESOURCE)
        .param("days", "90")
        .param("count", "1")
        .param("startIndex", "1"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(2)))
      .andExpect(jsonPath("$.Resources.length()", is(1)));
  }
}
