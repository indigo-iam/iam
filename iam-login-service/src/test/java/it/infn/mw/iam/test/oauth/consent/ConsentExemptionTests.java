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
package it.infn.mw.iam.test.oauth.consent;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Set;

import org.assertj.core.util.Sets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.consent.ConsentExemptionService;
import it.infn.mw.iam.persistence.model.ConsentExemption;
import it.infn.mw.iam.persistence.repository.IamConsentExemptionRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ConsentExemptionTests extends EndpointsTestUtils {

  @Autowired
  ConsentExemptionService exemptionService;

  @Autowired
  IamConsentExemptionRepository exemptionRepository;

  protected ConsentExemption getConsentExemptionFor(String creator, String clientId,
      Set<String> scopes) {

    ConsentExemption ws = new ConsentExemption();

    ws.setCreatorUserId(creator);
    ws.setClientId(clientId);
    ws.setAllowedScopes(scopes);

    return ws;
  }

  @BeforeEach
  void cleanUp() {
    exemptionRepository.deleteAll();
  }

  @Test
  void testConsentExemptionWithDeviceCodeDoesNotPromptToConsentPage() throws Exception {

    ConsentExemption ws = getConsentExemptionFor(ADMIN_USERNAME, DEVICE_CODE_CLIENT_ID,
        Sets.newLinkedHashSet("openid", "profile"));
    ws = exemptionService.save(ws);

    String response = mvc
      .perform(post(DEVICE_CODE_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED)
        .with(httpBasic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET))
        .param("client_id", "device-code-client")
        .param("scope", "openid"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.user_code").isString())
      .andExpect(jsonPath("$.device_code").isString())
      .andExpect(jsonPath("$.verification_uri", equalTo(DEVICE_USER_URL)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode responseJson = mapper.readTree(response);
    String userCode = responseJson.get("user_code").asText();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(DEVICE_USER_URL))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost:8080/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc.perform(get("http://localhost:8080/login").session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/login"))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", ADMIN_USERNAME)
        .param("password", ADMIN_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl(DEVICE_USER_URL))
      .andReturn()
      .getRequest()
      .getSession();

    mvc.perform(post(DEVICE_USER_VERIFY_URL).param("user_code", userCode).session(session))
      .andExpect(status().isOk())
      .andExpect(view().name("deviceApproved"));

    exemptionService.remove(ws);

  }

}
