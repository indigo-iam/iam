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
package it.infn.mw.iam.test.oauth.introspection;

import static it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint.ACCESS_TOKEN;
import static it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint.REFRESH_TOKEN;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.ResultActions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class IntrospectionEndpointTests extends EndpointsTestUtils {

  @Value("${iam.organisation.name}")
  String organisationName;

  @Value("${iam.issuer}")
  String issuer;

  @Autowired
  IamClientRepository clientRepository;

  @Autowired
  IamAccountRepository accountRepository;

  @Autowired
  TokenRevocationService revokeService;

  @Autowired
  ObjectMapper mapper;

  private ResultActions introspect(String username, String password, String tokenToIntrospect,
      TokenTypeHint tokenTypeHint) throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint.name()));
  }

  private ResultActions introspect(String username, String password, String tokenToIntrospect) throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect));
  }

  private ResultActions introspect(String tokenToIntrospect, TokenTypeHint tokenTypeHint)
      throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(anonymous())
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint.name()));
  }

  @Test
  public void testIntrospectionEndpointForbiddenForAnonymous() throws Exception {

    String accessToken = getPasswordAccessToken("openid");

    introspect(accessToken, ACCESS_TOKEN).andExpect(status().isUnauthorized());
  }

  @Test
  public void testIntrospectionEndpointForbiddenForBadCredentials() throws Exception {

    String accessToken = getPasswordAccessToken("openid");

    introspect("bad", "credentials", accessToken, ACCESS_TOKEN).andExpect(status().isUnauthorized());
  }

  @Test
  public void testIntrospectionEndpointReturnsBasicUserInformation() throws Exception {

    String accessToken = getPasswordAccessToken("openid");

    ClientDetailsEntity client = clientRepository.findByClientId(PASSWORD_CLIENT_ID).orElseThrow();
    IamAccount account = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.sub", equalTo(account.getUuid())))
      .andExpect(jsonPath("$.iss", equalTo(issuer)))
      .andExpect(jsonPath("$.client_id", equalTo(client.getClientId())))
      .andExpect(jsonPath("$.client_name", equalTo(client.getClientName())))
      .andExpect(jsonPath("$.exp").exists())
      .andExpect(jsonPath("$.scope", equalTo("openid")))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.given_name").doesNotExist())
      .andExpect(jsonPath("$.email").doesNotExist());
    // @formatter:on
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testIntrospectionEndpointWithRefreshToken() throws Exception {

    String refreshToken =
        getPasswordTokenResponse("openid profile offline_access").getRefreshToken().getValue();

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, refreshToken, REFRESH_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.exp", nullValue()))
      .andExpect(jsonPath("$.jti").exists());
    // @formatter:on
  }

  @Test
  public void testNoGroupsReturnedWithoutProfileScope() throws Exception {
    String accessToken = getPasswordAccessToken("openid");

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.preferred_username").doesNotExist())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.email").doesNotExist())
      .andExpect(jsonPath("$.email_verified").doesNotExist());
    // @formatter:on
  }

  @Test
  public void testEmailReturnedWithEmailScope() throws Exception {
    String accessToken = getPasswordAccessToken("openid email");

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.given_name").doesNotExist())
      .andExpect(jsonPath("$.family_name").doesNotExist())
      .andExpect(jsonPath("$.middle_name").doesNotExist())
      .andExpect(jsonPath("$.nickname").doesNotExist())
      .andExpect(jsonPath("$.picture").doesNotExist())
      .andExpect(jsonPath("$.updated_at").doesNotExist())
      .andExpect(jsonPath("$.preferred_username").doesNotExist())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")))
      .andExpect(jsonPath("$.email_verified", equalTo(true)));
    // @formatter:on
  }

  @Test
  public void testProfileClaimsReturnedWithProfileScope() throws Exception {
    String accessToken = getPasswordAccessToken("openid profile");
    IamAccount a = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.name", equalTo(a.getUserInfo().getName())))
      .andExpect(jsonPath("$.given_name", equalTo(a.getUserInfo().getGivenName())))
      .andExpect(jsonPath("$.family_name", equalTo(a.getUserInfo().getFamilyName())))
      .andExpect(jsonPath("$.middle_name").doesNotExist())
      .andExpect(jsonPath("$.nickname", equalTo(a.getUserInfo().getNickname())))
      .andExpect(jsonPath("$.picture").doesNotExist())
      .andExpect(jsonPath("$.updated_at", equalTo(a.getLastUpdateTime().toString())))
      .andExpect(jsonPath("$.preferred_username", equalTo(a.getUsername())))
      .andExpect(jsonPath("$.affiliation", equalTo(a.getUserInfo().getAffiliation())))
      .andExpect(jsonPath("$.updated_at").exists())
      .andExpect(jsonPath("$.email").doesNotExist())
      .andExpect(jsonPath("$.email_verified").doesNotExist());
    // @formatter:on
  }

  @Test
  public void testIntrospectRevokedAccessToken() throws Exception {
    String accessToken = getPasswordAccessToken("openid profile");

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    // @formatter:on

    revokeService.revokeToken(JWTParser.parse(accessToken), TokenTypeHint.ACCESS_TOKEN);

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @SuppressWarnings("deprecation")
  @Test
  public void testIntrospectRevokedRefreshToken() throws Exception {

    DefaultOAuth2AccessToken tokens = getPasswordTokenResponse("openid profile offline_access");
    String accessToken = tokens.getValue();
    String refreshToken = tokens.getRefreshToken().getValue();

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, refreshToken, REFRESH_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    // @formatter:on

    revokeService.revokeToken(JWTParser.parse(refreshToken), REFRESH_TOKEN);

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, refreshToken, REFRESH_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @Test
  public void testIntrospectWithInvalidToken() throws Exception {
    String accessToken = "invalid-token";

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testIntrospectTokensWithNoTokenTypeHint() throws Exception {

    DefaultOAuth2AccessToken tokens = getPasswordTokenResponse("openid profile offline_access");
    String accessToken = tokens.getValue();
    String refreshToken = tokens.getRefreshToken().getValue();
    IamAccount a = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.given_name", equalTo(a.getUserInfo().getGivenName())))
      .andExpect(jsonPath("$.family_name", equalTo(a.getUserInfo().getFamilyName())))
      .andExpect(jsonPath("$.preferred_username", equalTo(a.getUsername())));
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, refreshToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    // @formatter:on

    revokeService.revokeToken(JWTParser.parse(refreshToken), REFRESH_TOKEN);

    // @formatter:off
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, accessToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    introspect(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, refreshToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }
}
