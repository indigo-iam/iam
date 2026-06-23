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
package it.infn.mw.iam.test.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK, properties = {"iam.access_token.store_on_database=true"})
@AutoConfigureMockMvc
@Transactional
class IamTokenRepositoryTests extends TokenGetterUtils {

  static final String TEST_347_USER = "test_347";
  static final String TEST_346_USER = "test_346";

  static final String ISSUER = "issuer";
  static final String TEST_CLIEND_ID = "token-lookup-client";

  static final String[] SCOPES = {"openid", "profile", "offline_access", "iam:admin.read"};

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  AuthenticationHolderRepository authenticationHolderRepo;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  @Autowired
  TokenUtils tokenUtils;

  @BeforeEach
  void setup() {
    refreshTokenRepo.deleteAll();
    accessTokenRepo.deleteAll();
  }

  @Test
  void testTokenResolutionCorrectlyEnforcesUsernameChecks() throws Exception {

    context.useLocalUser(TEST_347_USER, PASSWORD_CLIENT_ID, USER_AUTHORITIES);
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_347_USER, "password",
        "openid offline_access");

    Date now = clock.now();

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_346_USER, now).size(), is(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_346_USER, now).size(), is(0));

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, now).size(), is(1));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, now).size(), is(1));
  }

  @Test
  void testExpiredTokensAreNotReturned() throws Exception {

    context.useLocalUser(TEST_347_USER, PASSWORD_CLIENT_ID, USER_AUTHORITIES);
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_347_USER, "password",
        "openid offline_access");

    clock.advance(Duration.ofHours(25L));

    Date now = clock.now();

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, now).size(), is(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, now).size(), is(0));
  }

  @Test
  void testClientTokensNotBoundToUsersAreIgnored() throws Exception {

    // create token as test user
    context.useLocalTestUser();
    getPasswordToken("openid offline_access");

    Date now = new Date();

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, now).size(), is(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, now).size(), is(0));
  }

  @Test
  void testRepositoryDoesntRelyOnDbTime() throws Exception {

    context.useLocalUser(TEST_347_USER, PASSWORD_CLIENT_ID, USER_AUTHORITIES);
    getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_347_USER, "password",
        "openid offline_access");

    clock.advance(Duration.ofDays(2L));

    Date current = clock.now();
    Date before = Date.from(clock.daysBefore(2));

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, before).size(), is(1));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, before).size(), is(1));

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, current).size(), is(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, current).size(),
        is(0));
  }

  @Test
  void testTokenNoCascadeDeletion() throws Exception {

    context.useLocalUser(TEST_347_USER, PASSWORD_CLIENT_ID, USER_AUTHORITIES);
    TokenEndpointResponse response = getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET,
        TEST_347_USER, "password", "openid offline_access");

    OAuth2AccessTokenEntity at =
        accessTokenRepo.findByTokenValue(tokenUtils.sha256(response.accessToken())).orElseThrow();
    OAuth2RefreshTokenEntity rt = at.getRefreshToken();
    AuthenticationHolderEntity ah = at.getAuthenticationHolder();
    accessTokenRepo.delete(at);
    assertThat(refreshTokenRepo.findById(rt.getId()).isEmpty(), is(false));
    assertThat(authenticationHolderRepo.getById(ah.getId()) != null, is(true));
    refreshTokenRepo.delete(rt);
    assertThat(refreshTokenRepo.findById(rt.getId()).isEmpty(), is(true));
    assertThat(authenticationHolderRepo.getById(ah.getId()) != null, is(true));
    authenticationHolderRepo.remove(ah);
    assertThat(authenticationHolderRepo.getById(ah.getId()) != null, is(false));
  }

  @Test
  void testTokenCascadeDeletion() throws Exception {

    context.useLocalUser(TEST_347_USER, PASSWORD_CLIENT_ID, USER_AUTHORITIES);
    TokenEndpointResponse response = getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET,
        TEST_347_USER, "password", "openid offline_access");

    OAuth2AccessTokenEntity at =
        accessTokenRepo.findByTokenValue(tokenUtils.sha256(response.accessToken())).orElseThrow();
    AuthenticationHolderEntity ah = at.getAuthenticationHolder();
    assertThat(accessTokenRepo.findAll()).hasSize(1);
    assertThat(refreshTokenRepo.findAll()).hasSize(1);
    assertThat(authenticationHolderRepo.getById(ah.getId()) != null, is(true));
    authenticationHolderRepo.remove(ah);
    assertThat(accessTokenRepo.findAll()).isEmpty();
    assertThat(refreshTokenRepo.findAll()).isEmpty();
    assertThat(authenticationHolderRepo.getById(ah.getId()) != null, is(false));
  }

  @Test
  void testAuthenticationHolderScopesLinkedToAccessAndRefreshTokens() throws Exception {

    context.useLocalUser(TEST_347_USER, PASSWORD_CLIENT_ID, USER_AUTHORITIES);
    TokenEndpointResponse response = getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET,
        TEST_347_USER, "password", "openid profile offline_access");

    OAuth2AccessTokenEntity at =
        accessTokenRepo.findByTokenValue(tokenUtils.sha256(response.accessToken())).orElseThrow();
    AuthenticationHolderEntity aht = at.getAuthenticationHolder();

    OAuth2RefreshTokenEntity rt = at.getRefreshToken();
    AuthenticationHolderEntity ahr = rt.getAuthenticationHolder();

    assertTrue(authenticationHolderRepo.getById(aht.getId()).getScope().contains("openid"));
    assertTrue(authenticationHolderRepo.getById(aht.getId()).getScope().contains("profile"));
    assertTrue(authenticationHolderRepo.getById(aht.getId()).getScope().contains("offline_access"));
    assertFalse(authenticationHolderRepo.getById(aht.getId()).getScope().contains("email"));

    assertTrue(authenticationHolderRepo.getById(ahr.getId()).getScope().contains("openid"));
    assertTrue(authenticationHolderRepo.getById(ahr.getId()).getScope().contains("profile"));
    assertTrue(authenticationHolderRepo.getById(ahr.getId()).getScope().contains("offline_access"));
    assertFalse(authenticationHolderRepo.getById(ahr.getId()).getScope().contains("email"));

    assertEquals(aht, ahr);
  }
}
