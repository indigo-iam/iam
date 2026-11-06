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
package it.infn.mw.iam.test.oauth;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;

/**
 * IAM cannot be requested as a resource or audience, so tokens requested for resources never
 * carry IAM in aud and, with require-iam-audience, cannot be used at IAM's APIs.
 */
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.protected-resources[0].id=data-api",
        "iam.protected-resources[0].resource=https://data.example.org/api",
        "iam.resource-indicators.restrict-to-protected-resources=true",
        "iam.resource-indicators.require-iam-audience=true",
        "iam.resource-indicators.allow-iam-audience-request=false"})
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class ForbidIamAudienceRequestTests {

  private static final String IAM = "http://localhost:8080";
  private static final String IAM_ISSUER = "http://localhost:8080/";
  private static final String DATA_API = "https://data.example.org/api";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  private static MockHttpServletRequestBuilder passwordGrant() {
    return post("/token").param("grant_type", "password")
      .param("client_id", "password-grant")
      .param("client_secret", "secret")
      .param("username", "test")
      .param("password", "password")
      .param("scope", "openid profile");
  }

  private String accessToken(MockHttpServletRequestBuilder request) throws Exception {
    String response = mvc.perform(request)
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    return mapper.readTree(response).get("access_token").asText();
  }

  private void expectInvalidTarget(MockHttpServletRequestBuilder request) throws Exception {
    mvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"));
  }

  @Test
  void testIamResourceIsRejected() throws Exception {
    expectInvalidTarget(passwordGrant().param("resource", IAM));
  }

  @Test
  void testIamResourceAmongOthersIsRejected() throws Exception {
    expectInvalidTarget(passwordGrant().param("resource", DATA_API + " " + IAM));
  }

  @Test
  void testRepeatedIamResourceIsRejected() throws Exception {
    expectInvalidTarget(passwordGrant().param("resource", DATA_API, IAM));
  }

  @Test
  void testIamIssuerAsAudienceIsRejected() throws Exception {
    expectInvalidTarget(passwordGrant().param("audience", IAM_ISSUER));
  }

  @Test
  void testIamAsAudParameterIsRejected() throws Exception {
    expectInvalidTarget(passwordGrant().param("aud", IAM));
  }

  @Test
  void testIamResourceIsRejectedAtDeviceAuthorizationEndpoint() throws Exception {
    expectInvalidTarget(post("/devicecode").contentType(APPLICATION_FORM_URLENCODED)
      .with(httpBasic("device-code-client", "secret"))
      .param("client_id", "device-code-client")
      .param("scope", "openid profile")
      .param("resource", IAM));
  }

  @Test
  void testTokenForOtherResourcesCannotBeUsedAtIam() throws Exception {
    String token = accessToken(passwordGrant().param("resource", DATA_API));

    mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
      .andExpect(status().isUnauthorized());
  }

  @Test
  void testTokenWithoutAudienceCanBeUsedAtIam() throws Exception {
    String token = accessToken(passwordGrant());

    mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
      .andExpect(status().isOk());
  }

  @Test
  void testIamIsStillListedAsProtectedResource() throws Exception {
    mvc.perform(get("/.well-known/oauth-authorization-server"))
      .andExpect(jsonPath("$.protected_resources[0]").value(IAM));
  }
}
