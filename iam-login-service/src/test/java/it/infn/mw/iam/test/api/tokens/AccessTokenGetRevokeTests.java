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
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.test.util.DateEqualModulo1Second;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class AccessTokenGetRevokeTests extends TestTokensUtils {

  public static final String[] SCOPES = {"openid", "profile"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";
  public static final String TEST_CLIENT2_ID = "password-grant";
  public static final int FAKE_TOKEN_ID = 12345;
  private static final String TESTUSER_USERNAME = "test_102";

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Before
  public void setup() {
    clearAllTokens();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    clearAllTokens();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void getAccessToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    IamAccount user = loadTestUser(TESTUSER_USERNAME);

    OAuth2AccessTokenEntity at = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, at.getId());

    AccessToken remoteAt =
        mapper.readValue(mvc.perform(get(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString(), AccessToken.class);

    System.out.println(remoteAt);

    assertThat(remoteAt.getId(), equalTo(at.getId()));
    assertThat(remoteAt.getValue(), nullValue()); 
    assertThat(remoteAt.getExpiration(), new DateEqualModulo1Second(at.getExpiration()));

    assertThat(remoteAt.getScopes().contains("openid"), equalTo(true));
    assertThat(remoteAt.getScopes().contains("profile"), equalTo(true));

    assertThat(remoteAt.getClient().getId(), equalTo(client.getId()));
    assertThat(remoteAt.getClient().getClientId(), equalTo(client.getClientId()));

    assertThat(remoteAt.getUser().getId(), equalTo(user.getUuid()));
    assertThat(remoteAt.getUser().getUserName(), equalTo(user.getUsername()));
    assertThat(remoteAt.getUser().getRef(),
        equalTo(scimResourceLocationProvider.userLocation(user.getUuid())));

  }

  @Test
  public void getAccessTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(get(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNotFound());
  }

  @Test
  public void revokeAccessToken() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    OAuth2AccessTokenEntity at = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, at.getId());

    mvc.perform(delete(path).contentType(APPLICATION_JSON_CONTENT_TYPE))
      .andExpect(status().isNoContent());

    assertThat(tokenService.getAccessTokenById(at.getId()), equalTo(null));
  }

  @Test
  public void revokeAccessTokenNotFound() throws JsonParseException, JsonMappingException,
      UnsupportedEncodingException, IOException, Exception {

    String path = String.format("%s/%d", ACCESS_TOKENS_BASE_PATH, FAKE_TOKEN_ID);
    mvc.perform(delete(path))
      .andExpect(status().isNotFound());
  }

  @Test
  public void testRevokeAllTokens() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);
    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    
    assertThat(accessTokenRepository.count(), equalTo(2L));
    
    mvc.perform(delete(ACCESS_TOKENS_BASE_PATH)).andExpect(status().isNoContent());
    
    assertThat(accessTokenRepository.count(), equalTo(0L));
  }
}
