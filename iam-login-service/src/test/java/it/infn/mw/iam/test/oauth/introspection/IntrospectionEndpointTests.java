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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class IntrospectionEndpointTests extends TokenGetterUtils {

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
  ResourceServerTokenServices tokenService;

  @Autowired
  IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  JWTSigningAndValidationService signService;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  MutableClock clock;

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

    String accessToken = getPasswordToken("openid").accessToken();

    clock.advance(Duration.ofHours(6));

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(false)));
    // @formatter:on
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
      .andExpect(jsonPath("$.exp").exists())
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

    OAuth2AccessTokenEntity at = (OAuth2AccessTokenEntity) tokenService.readAccessToken(accessToken);
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

    OAuth2RefreshTokenEntity rt = refreshTokenRepo.findByTokenValue(refreshToken).orElseThrow();
    revokeService.revokeRefreshToken(rt);

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken, ACCESS_TOKEN)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
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

    OAuth2RefreshTokenEntity rt = refreshTokenRepo.findByTokenValue(refreshToken).orElseThrow();
    revokeService.revokeRefreshToken(rt);

    // @formatter:off
    introspect(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET, accessToken)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));
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
