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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
 * By default IAM's own APIs keep accepting access tokens issued for other resources.
 */
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.protected-resources[0].id=data-api",
        "iam.protected-resources[0].resource=https://data.example.org/api",
        "iam.resource-indicators.require-iam-audience=false"})
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class IamAudienceNotRequiredTests {

  private static final String DATA_API = "https://data.example.org/api";

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
  void testTokenForAnotherResourceIsAccepted() throws Exception {
    mvc.perform(userinfo(accessToken("resource", DATA_API))).andExpect(status().isOk());
  }
}
