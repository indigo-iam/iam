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
package it.infn.mw.iam.test.api.tokens;

import static it.infn.mw.iam.api.tokens.TokensControllerSupport.APPLICATION_JSON_CONTENT_TYPE;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {"spring.main.allow-bean-definition-overriding=true",})
@Transactional
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"},
    scopes = {"iam:admin.read", "iam:admin.write"})
class RefreshTokenGetRevokeTests extends TestTokensUtils {

  static final String[] SCOPES = {"openid", "profile", "offline_access"};

  static final String TEST_CLIENT_ID = "token-lookup-client";
  static final String TEST_CLIENT2_ID = "password-grant";
  static final int FAKE_TOKEN_ID = 12345;
  static final String TESTUSER_USERNAME = "test_102";

  @Autowired
  ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  ObjectMapper mapper;

  @BeforeEach
  void setup() {
    clearAllTokens();
  }

  @AfterEach
  void teardown() {
    clearAllTokens();
  }

  @Test
  void getRefreshToken() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2RefreshTokenEntity rt =
        buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, rt.getId());

    RefreshToken remoteRt =
        mapper.readValue(mvc.perform(get(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString(), RefreshToken.class);

    System.out.println(remoteRt);

    assertThat(remoteRt.getId(), equalTo(rt.getId()));
    assertThat(remoteRt.getValue(), nullValue());
    assertThat(remoteRt.getExpiration(), equalTo(rt.getExpiration()));

    assertThat(remoteRt.getClient().getId(), equalTo(client.getId()));
    assertThat(remoteRt.getClient().getClientId(), equalTo(client.getClientId()));

    assertThat(remoteRt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteRt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteRt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));
  }

  @Test
  void getRefreshTokenNotFound() throws Exception {

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(get(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNotFound());
  }

  @Test
  void revokeRefreshToken() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    OAuth2RefreshTokenEntity rt =
        buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, rt.getId());

    mvc.perform(delete(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNoContent());

    assertThat(tokenService.getRefreshTokenById(rt.getId()), equalTo(null));
  }

  @Test
  void revokeRefreshTokenNotFound() throws Exception {

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNotFound());
  }

  @Test
  void testRevokeAllTokens() throws Exception {
    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();

    assertThat(refreshTokenRepository.count(), equalTo(2L));

    mvc.perform(delete(REFRESH_TOKENS_BASE_PATH)).andExpect(status().isNoContent());

    assertThat(refreshTokenRepository.count(), equalTo(0L));

  }
}
