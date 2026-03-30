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
package it.infn.mw.iam.test.api.scim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

@SpringBootTest(classes = {IamLoginService.class},
    properties = "iam.access_token.store_on_database=false")
@AutoConfigureMockMvc
@Transactional
public class ScimMockMvcTestSupport {

  protected static final String SCIM_BASE = "/scim";

  @Autowired
  protected MockMvc mockMvc;

  @Autowired
  protected ObjectMapper mapper;

  protected String clientCredentialsToken(String clientId, String secret, String scope)
      throws Exception {

    String body = "grant_type=client_credentials&scope=" + scope;

    MvcResult result = mockMvc
      .perform(post(StructuredScopeTestSupportConstants.TOKEN_ENDPOINT)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .content(body)
        .header("Authorization", basicAuth(clientId, secret)))
      .andReturn();

    assertEquals(200, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    return json.get("access_token").asText();
  }

  protected String passwordToken(String username, String password, String clientId,
      String clientSecret, String scope) throws Exception {

    String body = "grant_type=password" + "&username=" + username + "&password=" + password
        + "&scope=" + scope;

    MvcResult result = mockMvc
      .perform(post(StructuredScopeTestSupportConstants.TOKEN_ENDPOINT)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .content(body)
        .header("Authorization", basicAuth(clientId, clientSecret)))
      .andReturn();

    assertEquals(200, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    return json.get("access_token").asText();
  }

  protected static String basicAuth(String id, String secret) {
    return "Basic "
        + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }

  protected MvcResult authorizedPost(String url, String token, String json) throws Exception {

    return mockMvc
      .perform(post(url).header("Authorization", "Bearer " + token)
        .contentType("application/scim+json")
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
}
