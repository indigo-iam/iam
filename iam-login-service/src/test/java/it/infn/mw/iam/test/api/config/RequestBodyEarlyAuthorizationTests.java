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
package it.infn.mw.iam.test.api.config;

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_SECRET;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants.ADMIN_CLIENT_ID;
import static it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants.ADMIN_CLIENT_SECRET;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class RequestBodyEarlyAuthorizationTests {

  private static final String ACCOUNT_ID = "73f16d93-2441-4a50-88ff-85360d78c6b5";
  private static final String GROUP_ID = "f3b5d44e-20df-4c39-9a92-13230ecfd320";
  private static final String MALFORMED_JSON = "{ invalid json";

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper objectMapper;

  static Stream<Arguments> adminWriteEndpoints() {
    return Stream.of(Arguments.of(HttpMethod.PUT, "/iam/account/" + ACCOUNT_ID + "/endTime"),
        Arguments.of(HttpMethod.POST, "/api/scopes"),
        Arguments.of(HttpMethod.POST, "/iam/api/scopes"),
        Arguments.of(HttpMethod.PUT, "/api/scopes/1"),
        Arguments.of(HttpMethod.PUT, "/iam/api/scopes/1"),
        Arguments.of(HttpMethod.POST, "/iam/api/clients"),
        Arguments.of(HttpMethod.PUT, "/iam/api/clients/example-client"),
        Arguments.of(HttpMethod.POST, "/iam/scope_policies"),
        Arguments.of(HttpMethod.PUT, "/iam/scope_policies/1"),
        Arguments.of(HttpMethod.PUT, "/iam/account/" + ACCOUNT_ID + "/attributes"),
        Arguments.of(HttpMethod.PUT, "/iam/account/" + ACCOUNT_ID + "/labels"),
        Arguments.of(HttpMethod.PUT, "/iam/group/" + GROUP_ID + "/labels"),
        Arguments.of(HttpMethod.POST, "/iam/api/exchange/policies"),
        Arguments.of(HttpMethod.POST, "/api/blacklist"),
        Arguments.of(HttpMethod.POST, "/api/whitelist"),
        Arguments.of(HttpMethod.PATCH, "/iam/aup/signature/" + ACCOUNT_ID));
  }

  static Stream<Arguments> userRoleEndpoints() {
    return Stream.of(Arguments.of(HttpMethod.POST, "/iam/group_requests"),
        Arguments.of(HttpMethod.PUT, "/iam/account/me/proxycert"));
  }

  private MockHttpServletRequestBuilder malformedRequest(HttpMethod method, String path) {
    MockHttpServletRequestBuilder request;
    if (HttpMethod.POST.equals(method)) {
      request = post(path);
    } else if (HttpMethod.PUT.equals(method)) {
      request = put(path);
    } else if (HttpMethod.PATCH.equals(method)) {
      request = patch(path);
    } else {
      throw new IllegalArgumentException("Unsupported HTTP method: " + method);
    }
    return request.with(csrf().asHeader())
      .contentType(MediaType.APPLICATION_JSON)
      .content(MALFORMED_JSON);
  }

  @ParameterizedTest
  @MethodSource("adminWriteEndpoints")
  void nonAdminIsRejectedBeforeDeserialization(HttpMethod method, String path) throws Exception {
    mvc.perform(malformedRequest(method, path).with(user("member").roles("USER")))
      .andExpect(status().isForbidden());
  }

  @ParameterizedTest
  @MethodSource("adminWriteEndpoints")
  void adminReachesDeserialization(HttpMethod method, String path) throws Exception {
    mvc.perform(malformedRequest(method, path).with(user("admin").roles("USER", "ADMIN")))
      .andExpect(status().isBadRequest());
  }

  @ParameterizedTest
  @MethodSource("userRoleEndpoints")
  void nonUserIsRejectedBeforeDeserialization(HttpMethod method, String path) throws Exception {
    mvc.perform(malformedRequest(method, path).with(user("reader").roles("READER")))
      .andExpect(status().isForbidden());
  }

  @ParameterizedTest
  @MethodSource("userRoleEndpoints")
  void userReachesDeserialization(HttpMethod method, String path) throws Exception {
    mvc.perform(malformedRequest(method, path).with(user("member").roles("USER")))
      .andExpect(status().isBadRequest());
  }

  @Test
  void bearerWithoutAdminWriteScopeIsRejectedBeforeDeserialization() throws Exception {
    String token = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, SCIM_CLIENT_ID,
        SCIM_CLIENT_SECRET, SCIM_READ_SCOPE);

    mvc
      .perform(put("/iam/group/" + ACCOUNT_ID + "/attributes")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON)
        .content(MALFORMED_JSON))
      .andExpect(status().isForbidden());
  }

  static Stream<Arguments> bearerAdminWriteEndpoints() {
    return adminWriteEndpoints();
  }

  static Stream<Arguments> bearerScimWriteEndpoints() {
    return Stream.of(Arguments.of(HttpMethod.POST, "/scim/Users"),
        Arguments.of(HttpMethod.POST, "/scim/Groups"),
        Arguments.of(HttpMethod.PUT, "/scim/Users/" + ACCOUNT_ID),
        Arguments.of(HttpMethod.PUT, "/scim/Groups/" + GROUP_ID),
        Arguments.of(HttpMethod.PATCH, "/scim/Users/" + ACCOUNT_ID),
        Arguments.of(HttpMethod.PATCH, "/scim/Groups/" + GROUP_ID));
  }

  @ParameterizedTest
  @MethodSource("bearerAdminWriteEndpoints")
  void bearerWithoutAdminWriteScopeIsRejected(HttpMethod method, String path) throws Exception {
    String token = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, ADMIN_CLIENT_ID,
        ADMIN_CLIENT_SECRET, "iam:admin.read");
    mvc.perform(malformedRequest(method, path).with(OAuthTokenTestUtils.bearerToken(token)))
      .andExpect(status().isForbidden());
  }

  @ParameterizedTest
  @MethodSource("bearerAdminWriteEndpoints")
  void bearerWithAdminWriteScopeReachesDeserialization(HttpMethod method, String path)
      throws Exception {
    String token = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, ADMIN_CLIENT_ID,
        ADMIN_CLIENT_SECRET, "iam:admin.write");
    mvc.perform(malformedRequest(method, path).with(OAuthTokenTestUtils.bearerToken(token)))
      .andExpect(status().isBadRequest());
  }

  @ParameterizedTest
  @MethodSource("bearerScimWriteEndpoints")
  void bearerWithoutScimWriteScopeIsRejected(HttpMethod method, String path) throws Exception {
    String token = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, SCIM_CLIENT_ID,
        SCIM_CLIENT_SECRET, SCIM_READ_SCOPE);
    mvc.perform(malformedRequest(method, path).with(OAuthTokenTestUtils.bearerToken(token)))
      .andExpect(status().isForbidden());
  }

  @ParameterizedTest
  @MethodSource("bearerScimWriteEndpoints")
  void bearerWithScimWriteScopeReachesDeserialization(HttpMethod method, String path)
      throws Exception {
    String token = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, SCIM_CLIENT_ID,
        SCIM_CLIENT_SECRET, SCIM_WRITE_SCOPE);
    mvc.perform(malformedRequest(method, path).with(OAuthTokenTestUtils.bearerToken(token)))
      .andExpect(status().isBadRequest());
  }

  @Test
  void dashboardAdminReachesGroupAttributeDeserialization() throws Exception {
    mvc
      .perform(malformedRequest(HttpMethod.PUT, "/iam/group/" + ACCOUNT_ID + "/attributes")
        .with(user("admin").roles("ADMIN")))
      .andExpect(status().isBadRequest());
  }
}
