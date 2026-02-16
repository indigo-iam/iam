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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.time.DateUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.client.IamClientDetailsService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@IamNoMvcTest
@Transactional
public class IamTokenRepositoryTests {

  public static final String TEST_347_USER = "test_347";
  public static final String TEST_346_USER = "test_346";

  public static final String ISSUER = "issuer";
  public static final String TEST_CLIEND_ID = "token-lookup-client";

  public static final String[] SCOPES = {"openid", "profile", "offline_access", "iam:admin.read"};

  @Autowired
  private IamOAuthAccessTokenRepository atRepo;

  @Autowired
  private IamOAuthRefreshTokenRepository rtRepo;

  @Autowired
  private IamAuthenticationHolderRepository ahRepo;

  @Autowired
  private IamClientDetailsService clientDetailsService;

  @Autowired
  private IamTokenService tokenService;

  @BeforeEach
  void setup() {
    atRepo.deleteAll();
    rtRepo.deleteAll();
  }

  private OAuth2Authentication oauth2Authentication(ClientDetailsEntity client, String username) {

    String[] scopes = {};
    Authentication userAuth = null;
    Map<String, String> requestParameters = new HashMap<String, String>();
    requestParameters.put("grant_type", "authorization_code");

    if (username != null) {
      scopes = SCOPES;
      userAuth = new UsernamePasswordAuthenticationToken(username, "");
    }

    MockOAuth2Request req = new MockOAuth2Request(client.getClientId(), scopes);
    req.setRequestParameters(requestParameters);
    return new OAuth2Authentication(req, userAuth);

  }

  private ClientDetailsEntity loadTestClient() {
    return clientDetailsService.loadClientByClientId(TEST_CLIEND_ID);
  }

  private OAuth2AccessTokenEntity buildAccessToken(ClientDetailsEntity client, String username) {
    return tokenService.createAccessToken(oauth2Authentication(client, username));
  }

  private OAuth2AccessTokenEntity buildAccessToken(ClientDetailsEntity client) {
    return buildAccessToken(client, null);
  }

  @Test
  void testTokenResolutionCorrectlyEnforcesUsernameChecks() {

    buildAccessToken(loadTestClient(), TEST_347_USER);
    Date currentTimestamp = new Date();

    assertThat(atRepo.findValidAccessTokensForUser(TEST_346_USER, currentTimestamp), hasSize(0));
    assertThat(rtRepo.findValidRefreshTokensForUser(TEST_346_USER, currentTimestamp), hasSize(0));
    assertThat(atRepo.findValidAccessTokensForUser(TEST_347_USER, currentTimestamp), hasSize(1));
    assertThat(rtRepo.findValidRefreshTokensForUser(TEST_347_USER, currentTimestamp), hasSize(1));
  }

  @Test
  void testExpiredTokensAreNotReturned() {

    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_347_USER);

    Calendar cal = Calendar.getInstance();

    cal.add(Calendar.DAY_OF_YEAR, -1);

    Date yesterday = cal.getTime();

    at.setExpiration(yesterday);

    at.getRefreshToken().setExpiration(yesterday);
    
    atRepo.save(at);
    rtRepo.save(at.getRefreshToken());

    Date currentTimestamp = new Date();

    assertThat(atRepo.findValidAccessTokensForUser(TEST_347_USER, currentTimestamp), hasSize(0));
    assertThat(rtRepo.findValidRefreshTokensForUser(TEST_347_USER, currentTimestamp), hasSize(0));
  }

  @Test
  void testClientTokensNotBoundToUsersAreIgnored() {
    buildAccessToken(loadTestClient());
    Date currentTimestamp = new Date();

    assertThat(atRepo.findValidAccessTokensForUser(TEST_347_USER, currentTimestamp), hasSize(0));
    assertThat(rtRepo.findValidRefreshTokensForUser(TEST_347_USER, currentTimestamp), hasSize(0));
  }

  @Test
  void testRepositoryDoesntRelyOnDbTime() {
    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_347_USER);

    Date now = DateUtils.addHours(new Date(), -2);
    Date exp = DateUtils.addHours(now, +1);

    at.setExpiration(exp);
    at.getRefreshToken().setExpiration(exp);

    assertThat(atRepo.findValidAccessTokensForUser(TEST_347_USER, now), hasSize(1));
    assertThat(rtRepo.findValidRefreshTokensForUser(TEST_347_USER, now), hasSize(1));
  }

  @Test
  void testTokenNoCascadeDeletion() {

    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_347_USER);
    OAuth2RefreshTokenEntity rt = at.getRefreshToken();
    AuthenticationHolderEntity ah = at.getAuthenticationHolder();

    Long atId = at.getId();
    Long rtId = rt.getId();
    Long ahId = ah.getId();

    assertTrue(atRepo.findById(atId).isPresent());

    atRepo.delete(at);

    assertTrue(atRepo.findById(atId).isEmpty());
    assertTrue(rtRepo.findById(rtId).isPresent());
    assertTrue(ahRepo.findById(ahId).isPresent());

    rtRepo.deleteById(rtId);

    assertTrue(rtRepo.findById(rtId).isEmpty());
    assertTrue(ahRepo.findById(ahId).isPresent());

    ahRepo.deleteById(ahId);

    assertTrue(ahRepo.findById(ah.getId()).isEmpty());
  }

  @Test
  void testTokenCascadeDeletion() {

    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_347_USER);
    OAuth2RefreshTokenEntity rt = at.getRefreshToken();
    AuthenticationHolderEntity aht = at.getAuthenticationHolder();
    AuthenticationHolderEntity ahr = at.getAuthenticationHolder();

    rtRepo.save(rt); // on cascade also AuthenticationHolders and Access Token are saved

    assertTrue(atRepo.findById(at.getId()).isPresent());
    assertTrue(rtRepo.findById(rt.getId()).isPresent());
    assertTrue(ahRepo.findById(aht.getId()).isPresent());
    assertTrue(ahRepo.findById(ahr.getId()).isPresent());
    assertEquals(aht.getId(), ahr.getId());

    rtRepo.deleteById(rt.getId());
    rtRepo.flush();

    assertTrue(atRepo.findById(at.getId()).isEmpty());
    assertTrue(rtRepo.findById(rt.getId()).isEmpty());
    assertTrue(ahRepo.findById(aht.getId()).isPresent());
    assertTrue(ahRepo.findById(ahr.getId()).isPresent());

    ahRepo.delete(ahr);

    assertTrue(rtRepo.findById(rt.getId()).isEmpty());
    assertTrue(atRepo.findById(at.getId()).isEmpty());

  }

  @Test
  void testAuthenticationHolderScopesLinkedToAccessAndRefreshTokens() {

    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_347_USER);
    OAuth2RefreshTokenEntity rt = at.getRefreshToken();
    AuthenticationHolderEntity aht = at.getAuthenticationHolder();
    AuthenticationHolderEntity ahr = rt.getAuthenticationHolder();

    ahRepo.save(aht); // on cascade also Access Tokens and Refresh Tokens are saved

    assertTrue(ahRepo.getById(aht.getId()).getScope().contains("openid"));
    assertTrue(ahRepo.getById(aht.getId()).getScope().contains("profile"));
    assertTrue(ahRepo.getById(aht.getId()).getScope().contains("offline_access"));
    assertFalse(ahRepo.getById(aht.getId()).getScope().contains("iam:admin.read"));

    assertTrue(ahRepo.getById(ahr.getId()).getScope().contains("openid"));
    assertTrue(ahRepo.getById(ahr.getId()).getScope().contains("profile"));
    assertTrue(ahRepo.getById(ahr.getId()).getScope().contains("offline_access"));
    assertFalse(ahRepo.getById(ahr.getId()).getScope().contains("iam:admin.read"));
  }
}
