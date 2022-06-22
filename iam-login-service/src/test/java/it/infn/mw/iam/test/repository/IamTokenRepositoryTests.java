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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.time.DateUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;


@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamNoMvcTest
public class IamTokenRepositoryTests {

  public static final String TEST_347_USER = "test_347";
  public static final String TEST_346_USER = "test_346";

  public static final String ISSUER = "issuer";
  public static final String TEST_CLIEND_ID = "token-lookup-client";

  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  @Autowired
  private IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  private DefaultOAuth2ProviderTokenService tokenService;

  private OAuth2Authentication oauth2Authentication(ClientDetailsEntity client, String username) {

    String[] scopes = {};
    Authentication userAuth = null;

    if (username != null) {
      scopes = SCOPES;
      userAuth = new UsernamePasswordAuthenticationToken(username, "");
    }

    MockOAuth2Request req = new MockOAuth2Request(client.getClientId(), scopes);
    OAuth2Authentication auth = new OAuth2Authentication(req, userAuth);

    return auth;
  }

  private ClientDetailsEntity loadTestClient() {
    return clientDetailsService.loadClientByClientId(TEST_CLIEND_ID);
  }

  private OAuth2AccessTokenEntity buildAccessToken(ClientDetailsEntity client, String username) {
    OAuth2AccessTokenEntity token =
        tokenService.createAccessToken(oauth2Authentication(client, username));
    return token;
  }

  private OAuth2AccessTokenEntity buildAccessToken(ClientDetailsEntity client) {
    return buildAccessToken(client, null);
  }

  @Test
  public void testTokenResolutionCorrectlyEnforcesUsernameChecks() {

    buildAccessToken(loadTestClient(), TEST_347_USER);
    Date currentTimestamp = new Date();

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_346_USER, currentTimestamp),
        hasSize(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_346_USER, currentTimestamp),
        hasSize(0));

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, currentTimestamp),
        hasSize(1));

    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, currentTimestamp),
        hasSize(1));
  }

  @Test
  public void testExpiredTokensAreNotReturned() {

    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_347_USER);

    Calendar cal = Calendar.getInstance();

    cal.add(Calendar.DAY_OF_YEAR, -1);

    Date yesterday = cal.getTime();

    at.setExpiration(yesterday);
    
    at.getRefreshToken().setExpiration(yesterday);

    tokenService.saveAccessToken(at);
    tokenService.saveRefreshToken(at.getRefreshToken());

    Date currentTimestamp = new Date();

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, currentTimestamp),
        hasSize(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, currentTimestamp),
        hasSize(0));
  }

  @Test
  public void testClientTokensNotBoundToUsersAreIgnored() {
    buildAccessToken(loadTestClient());
    Date currentTimestamp = new Date();

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, currentTimestamp),
        hasSize(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, currentTimestamp),
        hasSize(0));
  }

  @Test
  public void testRepositoryDoesntRelyOnDbTime() {
    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_347_USER);

    Date now = DateUtils.addHours(new Date(), -2);
    Date exp = DateUtils.addHours(now, +1);

    at.setExpiration(exp);
    at.getRefreshToken().setExpiration(exp);

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_347_USER, now), hasSize(1));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_347_USER, now), hasSize(1));
  }

}
