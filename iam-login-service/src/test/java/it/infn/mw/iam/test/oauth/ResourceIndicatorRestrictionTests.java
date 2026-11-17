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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;

class ResourceIndicatorRestrictionTests extends ProtectedResourcesTestSupport {

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

  private MockHttpServletRequestBuilder userinfo(String accessToken) {
    return get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
  }

  @Test
  void testEveryRegisteredResourceIsInAudience() throws Exception {
    String token = accessToken(passwordGrant().param("resource", DATA_API, COMPUTE_API));

    assertThat(JWTParser.parse(token).getJWTClaimsSet().getAudience(),
        containsInAnyOrder(DATA_API, COMPUTE_API));
  }

  @Test
  void testUnregisteredResourcesAreRejected() throws Exception {
    mvc.perform(passwordGrant().param("resource", "https://example.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value(
          "The requested resource is not a registered protected resource: https://example.org"));

    expectInvalidTarget(passwordGrant().param("resource", DATA_API, "https://example.org"));
    expectInvalidTarget(passwordGrant().param("resource", DATA_API + "/v2"));
  }

  @Test
  void testIamAcceptsTokensForIam() throws Exception {
    mvc.perform(userinfo(accessToken(passwordGrant()))).andExpect(status().isOk());
    mvc.perform(userinfo(accessToken(passwordGrant().param("resource", IAM))))
      .andExpect(status().isOk());
    mvc.perform(userinfo(accessToken(passwordGrant().param("resource", IAM + " " + DATA_API))))
      .andExpect(status().isOk());
    mvc.perform(userinfo(accessToken(passwordGrant().param("audience", IAM + "/"))))
      .andExpect(status().isOk());
    mvc
      .perform(userinfo(
          accessToken(passwordGrant().param("audience", "https://wlcg.cern.ch/jwt/v1/any"))))
      .andExpect(status().isOk());
  }

  @Test
  void testIamRejectsTokensForOtherResources() throws Exception {
    String token = accessToken(passwordGrant().param("resource", DATA_API));

    mvc.perform(userinfo(token))
      .andExpect(status().isUnauthorized())
      .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
    mvc.perform(get("/scim/Me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
      .andExpect(status().isUnauthorized());
  }
}
