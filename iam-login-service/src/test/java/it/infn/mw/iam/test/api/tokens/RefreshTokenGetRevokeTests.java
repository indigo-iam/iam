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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class RefreshTokenGetRevokeTests extends TestTokensUtils {

  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private ObjectMapper mapper;

  private static final String TESTUSER_USERNAME = "test_102";

  @Before
  public void setup() {
    clearAllTokens();
  }

  @After
  public void teardown() {
    clearAllTokens();
  }

  @Test
  public void getRefreshToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

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
  public void getRefreshTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(get(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNotFound());
  }

  @Test
  public void revokeRefreshToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    OAuth2RefreshTokenEntity rt =
        buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, rt.getId());

    mvc.perform(delete(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNoContent());

    assertThat(tokenService.getRefreshTokenById(rt.getId()), equalTo(null));
  }

  @Test
  public void revokeRefreshTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", REFRESH_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNotFound());
  }

  @Test
  public void testRevokeAllTokens() throws Exception {
    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    buildAccessToken(client, TESTUSER_USERNAME, SCOPES).getRefreshToken();
    
    assertThat(refreshTokenRepository.count(), equalTo(2L));
    
    mvc.perform(delete(REFRESH_TOKENS_BASE_PATH)).andExpect(status().isNoContent());
    
    assertThat(refreshTokenRepository.count(), equalTo(0L));

  }
}
