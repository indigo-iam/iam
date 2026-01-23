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
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
class IntrospectionEndpointTests extends TestTokensUtils {

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
  IamTokenService tokenService;

  @Autowired
  JWTSigningAndValidationService signService;

  @Autowired
  ObjectMapper mapper;

  private ResultActions introspect(String username, String password, String tokenToIntrospect,
      TokenTypeHint tokenTypeHint) throws Exception {

    return introspect(username, password, tokenToIntrospect, tokenTypeHint.name());
  }

  private ResultActions introspect(String username, String password, String tokenToIntrospect,
      String tokenTypeHint) throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint));
  }

  private ResultActions introspect(String username, String password, String tokenToIntrospect)
      throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect));
  }

  private ResultActions introspect(String tokenToIntrospect, TokenTypeHint tokenTypeHint)
      throws Exception {

    return introspect(tokenToIntrospect, tokenTypeHint.name());
  }

  private ResultActions introspect(String tokenToIntrospect, String tokenTypeHint)
      throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(anonymous())
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint));
  }

  @Test
  void testIntrospectionEndpointForbiddenForAnonymous() throws Exception {

    String accessToken = getPasswordToken("openid").accessToken();

    introspect(accessToken, ACCESS_TOKEN).andExpect(status().isUnauthorized());
  }

  @Test
  void testIntrospectionEndpointForbiddenForBadCredentials() throws Exception {

    String accessToken = getPasswordToken("openid").accessToken();

    introspect("bad", "credentials", accessToken, ACCESS_TOKEN)
      .andExpect(status().isUnauthorized());
  }

  @Test
  void testIntrospectionEndpointInactiveWithEmptyStringToken() throws Exception {

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, "", ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, "", REFRESH_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @Test
  void testIntrospectionEndpointInactiveWithExpiredToken() throws Exception {

    ClientDetailsEntity client = clientRepository.findByClientId(PASSWORD_CLIENT_ID).orElseThrow();
    String accessToken = getExpiredAccessToken(client).getValue();

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  private OAuth2AccessTokenEntity getExpiredAccessToken(ClientDetailsEntity client) {

    return buildExpiredAccessToken(client, TEST_USERNAME, new String[] {"openid", "profile"});
  }

  @Test
  void testIntrospectionEndpointReturnsBasicUserInformation() throws Exception {

    String accessToken = getPasswordToken("openid").accessToken();

    ClientDetailsEntity client = clientRepository.findByClientId(PASSWORD_CLIENT_ID).orElseThrow();
    IamAccount account = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.sub", equalTo(account.getUuid())))
      .andExpect(jsonPath("$.iss", equalTo(issuer)))
      .andExpect(jsonPath("$.client_id", equalTo(client.getClientId())))
      .andExpect(jsonPath("$.exp").exists())
      .andExpect(jsonPath("$.scope", equalTo("openid")))
      .andExpect(jsonPath("$.groups").exists())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.email").doesNotExist());
    // @formatter:on
  }

  @Test
  void testIntrospectionEndpointWithRefreshToken() throws Exception {

    String refreshToken = getPasswordToken("openid profile offline_access").refreshToken();

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, refreshToken, REFRESH_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.client_id", equalTo("password-grant")))
      .andExpect(jsonPath("$.scope", 
          allOf(
              containsString("openid"),
              containsString("offline_access"),
              containsString("profile")
          )))
      .andExpect(jsonPath("$.exp").doesNotExist())
      .andExpect(jsonPath("$.jti").exists());
    // @formatter:on
  }

  @Test
  void testGroupsAndUsernameAreReturnedWhenUserIsTheSubject() throws Exception {
    String accessToken = getPasswordToken("openid").accessToken();
    IamAccount a = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    assertThat(a.getGroups().size(), is(3));

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.sub", equalTo(a.getUuid())))
      .andExpect(jsonPath("$.iss").exists())
      .andExpect(jsonPath("$.iss", equalTo(issuer)))
      .andExpect(jsonPath("$.iat").exists())
      .andExpect(jsonPath("$.jti").exists())
      .andExpect(jsonPath("$.client_id", equalTo(PASSWORD_CLIENT_ID)))
      .andExpect(jsonPath("$.username").exists())
      .andExpect(jsonPath("$.username", equalTo(TEST_USERNAME)))
      .andExpect(jsonPath("$.groups",
          allOf(
              containsString("Production"),
              containsString("Analysis")
          )));
    // @formatter:on
  }

  @Test
  void testGroupsAndUsernameAreNullWhenClientIsSubject() throws Exception {

    String accessToken = getClientCredentialsToken("openid profile").accessToken();
    IamAccount a = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();

    assertThat(a.getGroups().size(), is(3));

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.sub", equalTo(CLIENT_CREDENTIALS_CLIENT_ID)))
      .andExpect(jsonPath("$.iss").exists())
      .andExpect(jsonPath("$.iss", equalTo(issuer)))
      .andExpect(jsonPath("$.iat").exists())
      .andExpect(jsonPath("$.jti").exists())
      .andExpect(jsonPath("$.client_id", equalTo(CLIENT_CREDENTIALS_CLIENT_ID)))
      .andExpect(jsonPath("$.username").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist());
    // @formatter:on
  }

  @Test
  void testIntrospectRevokedAccessToken() throws Exception {
    String accessToken = getPasswordToken("openid profile").accessToken();

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    // @formatter:on

    OAuth2AccessTokenEntity at = tokenService.readAccessToken(accessToken);
    revokeService.revokeAccessToken(at);

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @Test
  void testIntrospectRevokedRefreshToken() throws Exception {

    TokenEndpointResponse tokens = getPasswordToken("openid profile offline_access");
    String accessToken = tokens.accessToken();
    String refreshToken = tokens.refreshToken();

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, refreshToken, REFRESH_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    // @formatter:on

    OAuth2RefreshTokenEntity rt = tokenService.getRefreshToken(refreshToken);
    revokeService.revokeRefreshToken(rt);

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, refreshToken, REFRESH_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @Test
  void testIntrospectWithInvalidToken() throws Exception {
    String accessToken = "invalid-token";

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @Test
  void testIntrospectTokensWithNoTokenTypeHint() throws Exception {

    TokenEndpointResponse tokens = getPasswordToken("openid profile offline_access");
    String accessToken = tokens.accessToken();
    String refreshToken = tokens.refreshToken();

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, refreshToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    // @formatter:on

    OAuth2RefreshTokenEntity rt = tokenService.getRefreshToken(refreshToken);
    revokeService.revokeRefreshToken(rt);

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, refreshToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
  }

  @Test
  void testIntrospectTokensWithNoTokenTypeLowerOrUpperCase() throws Exception {

    TokenEndpointResponse tokens = getPasswordToken("openid profile offline_access");
    String accessToken = tokens.accessToken();
    String refreshToken = tokens.refreshToken();

    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, "access_token")
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, "ACCESS_TOKEN")
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, refreshToken, "refresh_token")
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, refreshToken, "REFRESH_TOKEN")
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
  }

}
