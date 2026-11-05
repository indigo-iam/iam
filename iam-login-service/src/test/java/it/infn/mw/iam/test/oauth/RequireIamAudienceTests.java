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

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
 * IAM's own APIs only accept access tokens whose audience includes IAM.
 */
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.protected-resources[0].id=data-api",
        "iam.protected-resources[0].resource=https://data.example.org/api",
        "iam.resource-indicators.require-iam-audience=true"})
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class RequireIamAudienceTests {

  private static final String DATA_API = "https://data.example.org/api";
  private static final String RESOURCE_METADATA_PARAM =
      "resource_metadata=\"http://localhost:8080/.well-known/oauth-protected-resource\"";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  private String accessToken(String param, String value) throws Exception {
    MockHttpServletRequestBuilder request = post("/token").param("grant_type", "password")
      .param("client_id", "password-grant")
      .param("client_secret", "secret")
      .param("username", "test")
      .param("password", "password")
      .param("scope", "openid profile");
    if (param != null) {
      request.param(param, value);
    }
    String response = mvc.perform(request)
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    return mapper.readTree(response).get("access_token").asText();
  }

  private MockHttpServletRequestBuilder userinfo(String accessToken) {
    return get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
  }

  @Test
  void testTokenWithoutAudienceIsAccepted() throws Exception {
    mvc.perform(userinfo(accessToken(null, null))).andExpect(status().isOk());
  }

  @Test
  void testTokenForIamIsAccepted() throws Exception {
    mvc.perform(userinfo(accessToken("resource", "http://localhost:8080")))
      .andExpect(status().isOk());
  }

  @Test
  void testTokenForIamIssuerIsAccepted() throws Exception {
    mvc.perform(userinfo(accessToken("audience", "http://localhost:8080/")))
      .andExpect(status().isOk());
  }

  @Test
  void testTokenForIamAndAnotherResourceIsAccepted() throws Exception {
    mvc.perform(userinfo(accessToken("resource", "http://localhost:8080 " + DATA_API)))
      .andExpect(status().isOk());
  }

  @Test
  void testTokenForAnyWlcgAudienceIsAccepted() throws Exception {
    mvc.perform(userinfo(accessToken("audience", "https://wlcg.cern.ch/jwt/v1/any")))
      .andExpect(status().isOk());
  }

  @Test
  void testTokenForAnotherResourceIsRejected() throws Exception {
    mvc.perform(userinfo(accessToken("resource", DATA_API)))
      .andExpect(status().isUnauthorized())
      .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")))
      .andExpect(
          header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(RESOURCE_METADATA_PARAM)));
  }

  @Test
  void testTokenForAnotherResourceIsRejectedByScim() throws Exception {
    mvc.perform(get("/scim/Me").header(HttpHeaders.AUTHORIZATION,
        "Bearer " + accessToken("resource", DATA_API))).andExpect(status().isUnauthorized());
  }
}
