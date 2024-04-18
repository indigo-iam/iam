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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.TaskConfig;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@ActiveProfiles({"dev", "h2-test"})
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class TaskConfigTests extends EndpointsTestUtils {

  private static final String PASSWORD_GRANT_CLIENT_ID = "password-grant";

  @Autowired
  private IamTokenService iamTokenService;

  @Autowired
  private DefaultOAuth2AuthorizationCodeService iamAuthorizationCodeService;

  @Autowired
  private IamOAuthAccessTokenRepository aTokenRepository;

  @Autowired
  private IamOAuthRefreshTokenRepository rTokenRepository;

  @Autowired
  private AuthorizationCodeRepository authzCodeRepository;

  @Autowired
  private IamClientRepository clientRepository;

  @Autowired
  TaskConfig taskConfig;

  private ClientDetailsEntity client;

  @Before
  public void clearAll() {

    client = clientRepository.findByClientId(PASSWORD_GRANT_CLIENT_ID).get();
    iamTokenService.clearExpiredTokens();
    iamAuthorizationCodeService.clearExpiredAuthorizationCodes();
    addExpiredAccessAndRefreshTokens(10);
    addExpiredAuthorizationCode(5);
  }

  private void addExpiredAccessAndRefreshTokens(int count) {

    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DATE, -1);

    for (int i = 0; i < count; i++) {
      OAuth2RefreshTokenEntity rTokenEntity = new OAuth2RefreshTokenEntity();
      rTokenEntity.setExpiration(cal.getTime());
      rTokenEntity.setClient(client);
      JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("issuer")
        .expirationTime(cal.getTime())
        .subject(client.getClientId())
        .jwtID(UUID.randomUUID().toString())
        .build();
      rTokenEntity.setJwt(new PlainJWT(claims));
      rTokenRepository.save(rTokenEntity);
      OAuth2AccessTokenEntity aTokenEntity = new OAuth2AccessTokenEntity();
      aTokenEntity.setExpiration(cal.getTime());
      aTokenEntity.setClient(client);
      claims = new JWTClaimsSet.Builder().issuer("issuer")
        .expirationTime(cal.getTime())
        .subject(client.getClientId())
        .jwtID(UUID.randomUUID().toString())
        .build();
      JWT at = new PlainJWT(claims);
      aTokenEntity.setJwt(at);
      aTokenEntity.setScope(Sets.newHashSet("openid", "profile"));
      aTokenEntity.hashMe();
      aTokenRepository.save(aTokenEntity);
    }
  }

  private void addExpiredAuthorizationCode(int count) {

    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DATE, -1);

    for (int i = 0; i < count; i++) {
      AuthorizationCodeEntity codeEntity = new AuthorizationCodeEntity();
      codeEntity.setCode("code" + i);
      codeEntity.setExpiration(cal.getTime());
      authzCodeRepository.save(codeEntity);
    }
  }

  @Test
  public void clearUsingTaskConfigMethodsWorks() {

    Pageable pageRequest = Pageable.ofSize(10);

    taskConfig.clearExpiredTokens();
    assertThat(aTokenRepository.count() - aTokenRepository
      .findValidAccessTokensForClient(PASSWORD_GRANT_CLIENT_ID, new Date(), pageRequest)
      .getTotalElements(), is(0L));
    assertThat(rTokenRepository.count() - rTokenRepository
        .findValidRefreshTokensForClient(PASSWORD_GRANT_CLIENT_ID, new Date(), pageRequest)
        .getTotalElements(), is(0L));

    taskConfig.clearExpiredAuthorizationCodes();
    assertThat(authzCodeRepository.getExpiredCodes().size(), is(0));
  }
}
