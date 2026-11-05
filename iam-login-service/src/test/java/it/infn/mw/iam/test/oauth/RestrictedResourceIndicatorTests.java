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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;

/**
 * RFC 8707 resource indicators when they are restricted to the registered protected resources.
 */
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.protected-resources[0].id=data-api",
        "iam.protected-resources[0].resource=https://data.example.org/api",
        "iam.protected-resources[1].id=compute-api",
        "iam.protected-resources[1].resource=https://compute.example.org",
        "iam.resource-indicators.restrict-to-protected-resources=true"})
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class RestrictedResourceIndicatorTests {

  private static final String TOKEN_ENDPOINT = "/token";
  private static final String DATA_API = "https://data.example.org/api";
  private static final String COMPUTE_API = "https://compute.example.org";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  private static MockHttpServletRequestBuilder clientCredentials() {
    return post(TOKEN_ENDPOINT).param("grant_type", "client_credentials")
      .param("client_id", "client-cred")
      .param("client_secret", "secret");
  }

  private List<String> audience(MockHttpServletRequestBuilder request) throws Exception {
    String response = mvc.perform(request)
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    String accessToken = mapper.readTree(response).get("access_token").asText();
    return JWTParser.parse(accessToken).getJWTClaimsSet().getAudience();
  }

  @Test
  void testRegisteredResourceIsAccepted() throws Exception {
    assertThat(audience(clientCredentials().param("resource", DATA_API)),
        containsInAnyOrder(DATA_API));
  }

  @Test
  void testIamOwnResourceIsAccepted() throws Exception {
    assertThat(audience(clientCredentials().param("resource", "http://localhost:8080")),
        containsInAnyOrder("http://localhost:8080"));
  }

  @Test
  void testEveryRepeatedRegisteredResourceIsInAudience() throws Exception {
    assertThat(audience(clientCredentials().param("resource", DATA_API, COMPUTE_API)),
        containsInAnyOrder(DATA_API, COMPUTE_API));
  }

  @Test
  void testUnregisteredResourceIsRejected() throws Exception {
    mvc.perform(clientCredentials().param("resource", "https://example.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"))
      .andExpect(jsonPath("$.error_description").value(
          "The requested resource is not a registered protected resource: https://example.org"));
  }

  @Test
  void testRepeatedResourcesWithOneUnregisteredAreRejected() throws Exception {
    mvc.perform(clientCredentials().param("resource", DATA_API, "https://example.org"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"));
  }

  @Test
  void testResourcesMustMatchExactly() throws Exception {
    mvc.perform(clientCredentials().param("resource", DATA_API + "/v2"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"));
  }

  @Test
  void testRequestWithoutResourceIsUnaffected() throws Exception {
    mvc.perform(clientCredentials()).andExpect(status().isOk());
  }
}
