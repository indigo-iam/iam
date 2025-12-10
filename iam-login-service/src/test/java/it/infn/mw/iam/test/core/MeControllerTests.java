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
package it.infn.mw.iam.test.core;

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {"spring.main.allow-bean-definition-overriding=true",})
@Transactional
class MeControllerTests {

  static final String TESTUSER_USERNAME = "test_101";
  static final String NOT_FOUND_USERNAME = "not_found";

  @Autowired
  MockMvc mvc;

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  ObjectMapper mapper;

  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, scopes = {})
  void insufficientScopeUser() throws Exception {

    mvc.perform(get(ScimUtils.getMeLocation())).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TESTUSER_USERNAME, roles = {})
  void insufficientAuthoritiesUser() throws Exception {

    mvc.perform(get(ScimUtils.getMeLocation())).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = NOT_FOUND_USERNAME, scopes = {SCIM_READ_SCOPE})
  void notFoundUserWithToken() throws Exception {

    mvc.perform(get(ScimUtils.getMeLocation())).andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(username = NOT_FOUND_USERNAME, roles = {"USER"})
  void notFoundUser() throws Exception {

    mvc.perform(get(ScimUtils.getMeLocation())).andExpect(status().isNotFound());
  }

  @Test
  @WithMockOAuthUser(user = TESTUSER_USERNAME, scopes = {SCIM_READ_SCOPE})
  void authenticatedUserWithToken() throws Exception {

    ScimUser user = mapper.readValue(mvc.perform(get(ScimUtils.getMeLocation()))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andReturn()
      .getResponse()
      .getContentAsString(), ScimUser.class);

    assertEquals(TESTUSER_USERNAME, user.getUserName());
  }

  @Test
  @WithMockUser(username = TESTUSER_USERNAME, roles = {"USER"})
  void authenticatedUserNoToken() throws Exception {

    ScimUser user = mapper.readValue(mvc.perform(get(ScimUtils.getMeLocation()))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andReturn()
      .getResponse()
      .getContentAsString(), ScimUser.class);

    assertEquals(TESTUSER_USERNAME, user.getUserName());
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE})
  void notAuthorizedClient() throws Exception {

    mvc.perform(get(ScimUtils.getMeLocation()))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.detail", is("No user linked to the current OAuth token")));
  }
}
