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
package it.infn.mw.iam.test.api.account.lifecycle;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import java.util.Date;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.lifecycle.AccountLifecycleDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@Transactional
class AccountLifecycleApiTests implements StructuredScopeTestSupportConstants {

  static final String END_TIME_RESOURCE = "/iam/account/{id}/endTime";

  static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";

  @Autowired
  IamAccountRepository repo;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MockMvc mvc;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  @Test
  @WithAnonymousUser
  void managingEndTimeRequiresAuthenticatedUser() throws Exception {
    AccountLifecycleDTO dto = new AccountLifecycleDTO();
    mvc
      .perform(put(END_TIME_RESOURCE, TEST_100_USER_UUID).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(UNAUTHORIZED);
  }

  @Test
  @WithMockUser(username = "test")
  void managingEndTimeFailsForNormalUser() throws Exception {
    AccountLifecycleDTO dto = new AccountLifecycleDTO();
    mvc
      .perform(put(END_TIME_RESOURCE, TEST_100_USER_UUID).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(FORBIDDEN);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void managingEndTimeRequiresAdminUser() throws Exception {
    Date newEndTime = new Date();
    AccountLifecycleDTO dto = new AccountLifecycleDTO();
    dto.setEndTime(newEndTime);

    mvc
      .perform(put(END_TIME_RESOURCE, TEST_100_USER_UUID).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(OK);

    IamAccount account =
        repo.findByUuid(TEST_100_USER_UUID).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    
    assertThat(account.getEndTime(), is(newEndTime));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = "ROLE_ADMIN", scopes = "iam:admin.write")
  void setEndTimeWorksForAdminUserWithScope() throws Exception {
    Date newEndTime = new Date();
    AccountLifecycleDTO dto = new AccountLifecycleDTO();
    dto.setEndTime(newEndTime);

    mvc
      .perform(put(END_TIME_RESOURCE, TEST_100_USER_UUID).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(OK);
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = "ROLE_ADMIN")
  void setEndTimeDoesNotWork() throws Exception {
    Date newEndTime = new Date();
    AccountLifecycleDTO dto = new AccountLifecycleDTO();
    dto.setEndTime(newEndTime);

    mvc
      .perform(put(END_TIME_RESOURCE, TEST_100_USER_UUID).content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(FORBIDDEN);
  }




}
