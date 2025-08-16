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
package it.infn.mw.iam.test.core.gc;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.text.ParseException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.service.AuthenticationHolderEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.junit4.SpringRunner;

import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.core.gc.GarbageCollector;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class DefaultGarbageCollectorTests extends TestTokensUtils {

  @Autowired
  private GarbageCollector gc;

  @Autowired
  private AuthorizationCodeRepository authzCodeRepo;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  private IamRevokedAccessTokenRepository revokedAccessTokenRepo;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private AuthenticationHolderEntityService authenticationHolderService;

  private final Date EXPIRED_DATE =
      Date.from(LocalDate.now().minusMonths(1).atStartOfDay(ZoneId.systemDefault()).toInstant());
  private final Pageable DEFAULT_PAGE = new OffsetPageable(0, 100);
  private final String EXPIRED_JWT = "eyJhbGciOiJub25lIiwia2lkIjoicnNhMSJ9.eyJzdWIiOiI4MGU1ZmI4ZC1iN2M4LTQ1MWEtODliYS0zNDZhZTI3OGE2NmYiLCJjbGllbnRfaWQiOiJjbGllbnQiLCJpYXQiOjE3MTg4OTk1NjEsImV4cCI6MTcxODg5OTU2MX0.";

  @Before
  public void cleanAllObjects() {
    gc.clearExpiredAuthorizationCodes();
    gc.clearExpiredTokens();
    gc.clearExpiredRevokedTokens();
  }

  @Test
  public void testExpiredAuthorizationCodesAreRemoved() {

    // create expired authorization code
    String[] scopes = {"opeind", "profile"};
    ClientDetailsEntity client = clientRepo.findByClientId("client").orElseThrow();
    OAuth2Authentication authn = oauth2Authentication(client, "test", scopes);
    AuthenticationHolderEntity authHolder = authenticationHolderService.create(authn);
    AuthorizationCodeEntity entity = new AuthorizationCodeEntity("ABCDEF", authHolder, EXPIRED_DATE);
    authzCodeRepo.save(entity);

    assertThat(authzCodeRepo.getExpiredCodes().size(), is(1));
    gc.clearExpiredAuthorizationCodes();
    assertThat(authzCodeRepo.getExpiredCodes().size(), is(0));
  }

  @Test
  public void testExpiredTokensAreRemoved() throws ParseException {

    // create expired refresh token
    String[] scopes = {"opeind", "profile"};
    ClientDetailsEntity client = clientRepo.findByClientId("client").orElseThrow();
    OAuth2Authentication authn = oauth2Authentication(client, "test", scopes);
    AuthenticationHolderEntity authHolder = authenticationHolderService.create(authn);
    OAuth2RefreshTokenEntity entity = new OAuth2RefreshTokenEntity();
    entity.setJwt(PlainJWT.parse(EXPIRED_JWT));
    entity.setAuthenticationHolder(authHolder);
    entity.setClient(client);
    entity.setExpiration(EXPIRED_DATE);
    entity = refreshTokenRepo.save(entity);

    assertThat(refreshTokenRepo.findExpiredTokens(DEFAULT_PAGE).getContent().isEmpty(), is(false));
    assertThat(refreshTokenRepo.findExpiredTokens(DEFAULT_PAGE).getContent().size(), is(1));
    gc.clearExpiredTokens();
    assertThat(refreshTokenRepo.findExpiredTokens(DEFAULT_PAGE).getContent().isEmpty(), is(true));
    assertThat(refreshTokenRepo.findExpiredTokens(DEFAULT_PAGE).getContent().size(), is(0));
  }

  @Test
  public void testExpiredRevokedTokensAreRemoved() {

    // create expired revoked code
    IamRevokedAccessToken entity = new IamRevokedAccessToken();
    entity.setJti("ABCDEF");
    entity.setExpiration(EXPIRED_DATE);
    revokedAccessTokenRepo.save(entity);
    
    assertThat(revokedAccessTokenRepo.findExpired(DEFAULT_PAGE).getContent().isEmpty(), is(false));
    assertThat(revokedAccessTokenRepo.findExpired(DEFAULT_PAGE).getContent().size(), is(1));
    gc.clearExpiredRevokedTokens();
    assertThat(revokedAccessTokenRepo.findExpired(DEFAULT_PAGE).getContent().isEmpty(), is(true));
    assertThat(revokedAccessTokenRepo.findExpired(DEFAULT_PAGE).getContent().size(), is(0));
  }

}
