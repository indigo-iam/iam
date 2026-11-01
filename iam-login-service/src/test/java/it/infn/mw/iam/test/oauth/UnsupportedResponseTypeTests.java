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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
public class UnsupportedResponseTypeTests extends TokenGetterUtils {

  public static final String LOGIN_URL = "http://localhost/login";
  public static final String AUTHORIZE_URL = "http://localhost/authorize";

  public static final String SCOPE = "openid profile";

  @Autowired
  ObjectMapper objectMapper;

  @Autowired
  IamAupRepository aupRepo;

  @Autowired
  MockMvc mvc;

  @Autowired
  IamClientRepository clientRepo;

  private ResultMatcher unsupportedResponseTypeError() {
    return result -> {
      status().isBadRequest().match(result);
      header().doesNotExist(HttpHeaders.LOCATION).match(result);
      jsonPath("$.error")
        .value("unsupported_response_type")
        .match(result);
      jsonPath("$.error_description")
        .value("Only response_type=code is supported")
        .match(result);
    };
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "token",
      "id_token",
      "token id_token",
      "id_token token",
      "code token",
      "code id_token",
      "code token id_token"
  })
  @WithMockUser(username = "test", roles = {"USER"})
  void unsupportedResponseTypeIsRejectedLocally(String responseType)
      throws Exception {

    mvc.perform(get("/authorize")
        .param("client_id", TEST_CLIENT_ID)
        .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .param("response_type", responseType)
        .param("scope", "openid profile")
        .param("nonce", "test-nonce")
        .param("state", "test-state"))
      .andExpect(unsupportedResponseTypeError());
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "token",
      "id_token",
      "token id_token",
      "id_token token",
      "code token",
      "code id_token",
      "code token id_token"
  })
  @WithMockUser(username = "test", roles = {"USER"})
  void unsupportedResponseTypeDoesNotRedirectToUnregisteredUri(
      String responseType) throws Exception {

    mvc.perform(get("/authorize")
        .param("client_id", TEST_CLIENT_ID)
        .param("redirect_uri", "https://attacker.example/callback")
        .param("response_type", responseType)
        .param("scope", "openid profile")
        .param("nonce", "test-nonce")
        .param("state", "test-state"))
      .andExpect(unsupportedResponseTypeError());
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "token",
      "id_token",
      "token id_token",
      "id_token token",
      "code token",
      "code id_token",
      "code token id_token"
  })
  @WithMockUser(username = "test", roles = {"USER"})
  void legacyClientCannotUseUnsupportedResponseTypes(String responseType)
      throws Exception {

    ClientDetailsEntity client =
        clientRepo.findByClientId(TEST_CLIENT_ID).orElseThrow();

    client.setGrantTypes(Set.of("authorization_code", "implicit"));
    client.setResponseTypes(Set.of("code", "token"));
    clientRepo.saveAndFlush(client);

    mvc.perform(get("/authorize")
        .param("client_id", TEST_CLIENT_ID)
        .param("redirect_uri", TEST_CLIENT_REDIRECT_URI)
        .param("response_type", responseType)
        .param("scope", "openid profile")
        .param("nonce", "test-nonce")
        .param("state", "test-state"))
      .andExpect(unsupportedResponseTypeError());
  }
}
