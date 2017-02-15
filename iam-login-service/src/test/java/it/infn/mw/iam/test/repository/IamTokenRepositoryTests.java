package it.infn.mw.iam.test.repository;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.junit.Assert.assertThat;

import java.util.Date;

import javax.persistence.EntityManager;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class})
@WebIntegrationTest
@Transactional
public class IamTokenRepositoryTests {

  public static final String TEST_USER = "test";
  public static final String ADMIN_USER = "admin";
  public static final String ISSUER = "issuer";
  public static final String TEST_CLIEND_ID = "client";

  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  ClientDetailsEntityService clientDetailsService;

  @Autowired
  DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  EntityManager em;

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

    buildAccessToken(loadTestClient(), TEST_USER);

    assertThat(accessTokenRepo.findValidAccessTokensForUser(ADMIN_USER), hasSize(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(ADMIN_USER), hasSize(0));

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_USER), hasSize(2)); // access token
                                                                                     // + ID token

    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_USER), hasSize(1));
  }

  @Test
  public void testExpiredTokensAreNotReturned() {

    OAuth2AccessTokenEntity at = buildAccessToken(loadTestClient(), TEST_USER);

    Date now = new Date();
    at.setExpiration(now);
    at.getIdToken().setExpiration(now);
    at.getRefreshToken().setExpiration(now);

    tokenService.saveAccessToken(at);
    tokenService.saveAccessToken(at.getIdToken());
    tokenService.saveRefreshToken(at.getRefreshToken());

    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_USER), hasSize(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_USER), hasSize(0));
  }

  @Test
  public void testClientTokensNotBoundToUsersAreIgnored() {
    buildAccessToken(loadTestClient());

    assertThat(accessTokenRepo.findAll(), iterableWithSize(1));
    assertThat(refreshTokenRepo.findAll(), iterableWithSize(0));
    assertThat(accessTokenRepo.findValidAccessTokensForUser(TEST_USER), hasSize(0));
    assertThat(refreshTokenRepo.findValidRefreshTokensForUser(TEST_USER), hasSize(0));
  }

}
