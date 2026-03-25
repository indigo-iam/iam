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
package it.infn.mw.iam.test.util.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

@SpringBootTest(classes = {IamLoginService.class},
    properties = "iam.access_token.store_on_database=false")
@AutoConfigureMockMvc
public abstract class OidcMockMvcTestSupport implements StructuredScopeTestSupportConstants {

  @Autowired
  protected MockMvc mockMvc;

  protected ObjectMapper mapper;

  @BeforeEach
  void setupMapper() {
    mapper = new ObjectMapper();
  }

  protected MvcResult postForm(String endpoint, Map<String, String> params) throws Exception {

    return postForm(endpoint, params, null, null);
  }

  protected MvcResult postForm(String endpoint, Map<String, String> params, String username,
      String password) throws Exception {

    String body = params.entrySet()
      .stream()
      .map(e -> e.getKey() + "=" + e.getValue())
      .collect(Collectors.joining("&"));

    var request = post(endpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED)
      .content(body)
      .characterEncoding(StandardCharsets.UTF_8);

    if (username != null && password != null) {
      request.with(httpBasic(username, password));
    }

    return mockMvc.perform(request).andReturn();
  }

  protected JsonNode assert200AndParse(MvcResult result) throws Exception {
    assertEquals(200, result.getResponse().getStatus());
    return mapper.readTree(result.getResponse().getContentAsString());
  }

  protected JsonNode introspect(String token) throws Exception {

    var result = postForm(INTROSPECTION_ENDPOINT, Map.of("token", token), PROTECTED_RESOURCE_ID,
        PROTECTED_RESOURCE_SECRET);

    return assert200AndParse(result);
  }

  protected String clientCredentialsToken(String clientId, String secret, String scope)
      throws Exception {

    String body = "grant_type=client_credentials&scope=" + scope;

    MvcResult result = mockMvc
      .perform(post(TOKEN_ENDPOINT).contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .content(body)
        .with(httpBasic(clientId, secret)))
      .andReturn();

    assertEquals(200, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    return json.get("access_token").asText();
  }

  protected String passwordToken(String scope, String username, String password) throws Exception {

    String body = "grant_type=password" + "&username=" + username + "&password=" + password
        + "&scope=" + scope;

    MvcResult result = mockMvc
      .perform(post(TOKEN_ENDPOINT).contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .content(body)
        .with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET)))
      .andReturn();

    assertEquals(200, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    return json.get("access_token").asText();
  }

  protected String passwordIdToken(String scope, String username, String password) throws Exception {

    String body = "grant_type=password" + "&username=" + username + "&password=" + password
        + "&scope=" + scope;

    MvcResult result = mockMvc
      .perform(post(TOKEN_ENDPOINT).contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .content(body)
        .with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET)))
      .andReturn();

    assertEquals(200, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    return json.get("id_token").asText();
  }

  protected MvcResult authorizedPost(String url, String token, String json) throws Exception {

    return mockMvc
      .perform(post(url).header("Authorization", "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON)
        .content(json))
      .andReturn();
  }

  protected MvcResult authorizedPatch(String url, String token, String json) throws Exception {

    return mockMvc
      .perform(patch(url).header("Authorization", "Bearer " + token)
        .contentType("application/scim+json")
        .content(json))
      .andReturn();
  }

  protected MvcResult authorizedDelete(String url, String token) throws Exception {

    return mockMvc.perform(delete(url).header("Authorization", "Bearer " + token)).andReturn();
  }

  protected MvcResult authorizedGet(String url, String token) throws Exception {

    return mockMvc.perform(get(url).header("Authorization", "Bearer " + token)).andReturn();
  }

  protected void assertForbidden(MvcResult result) {
    assertEquals(403, result.getResponse().getStatus());
  }
}
