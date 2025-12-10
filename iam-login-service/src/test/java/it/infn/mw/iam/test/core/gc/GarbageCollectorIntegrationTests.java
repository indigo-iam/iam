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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.exception.DeviceCodeCreationException;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.AuthenticationHolderEntityService;
import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.gc.GarbageCollector;
import it.infn.mw.iam.persistence.repository.IamApprovedSiteRepository;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.IamDeviceCodeRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class})
@TestPropertySource(properties = "scheduling.enabled=false")
class GarbageCollectorIntegrationTests extends TestTokensUtils {

  @Autowired
  GarbageCollector gc;

  @Autowired
  private ApprovedSiteService approvedSiteService;

  @Autowired
  private IamApprovedSiteRepository siteRepository;

  @Autowired
  private IamAuthorizationCodeRepository codeRepository;

  @Autowired
  private AuthenticationHolderEntityService authenticationHolderService;

  @Autowired
  private IamAuthenticationHolderRepository authenticationHolderRepository;

  @Autowired
  private OAuth2TokenEntityService tokenService;

  @Autowired
  private IamOAuthAccessTokenRepository accessTokenRepository;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepository;

  @Autowired
  private DeviceCodeService codeService;

  @Autowired
  private IamDeviceCodeRepository deviceCodeRepository;

  private AuthorizationCodeEntity createAuthorizationCode() {
    OAuth2Authentication auth = getOAuth2Authentication();
    RandomValueStringGenerator generator = new RandomValueStringGenerator(22);
    AuthenticationHolderEntity authHolder = authenticationHolderService.create(auth);
    return new AuthorizationCodeEntity(generator.generate(), authHolder, yesterday());
  }

  private OAuth2Authentication getOAuth2Authentication() {
    return getOAuth2Authentication(Set.of("openid"));
  }

  private OAuth2Authentication getOAuth2Authentication(Set<String> scopes) {
    return oauth2Authentication(loadTestClient(PASSWORD_CLIENT_ID), TEST_USERNAME,
        scopes.toArray(new String[0]));
  }

  @BeforeEach
  void cleanAll() {
    siteRepository.deleteAll();
    codeRepository.deleteAll();
    accessTokenRepository.deleteAll();
    refreshTokenRepository.deleteAll();
    deviceCodeRepository.deleteAll();
    authenticationHolderRepository.deleteAll();
  }

  @Test
  @Transactional
  void clearExpiredApprovedSites() {

    assertThat(siteRepository.count(), equalTo(0L));
    approvedSiteService.createApprovedSite(PASSWORD_CLIENT_ID, TEST_USERNAME, yesterday(),
        Set.of("openid"));
    assertThat(siteRepository.count(), equalTo(1L));
    gc.clearExpiredApprovedSites(1);
    assertThat(siteRepository.count(), equalTo(0L));
  }

  @Test
  @Transactional
  void clearExpiredAuthorizationCodes() {

    assertThat(codeRepository.count(), equalTo(0L));
    codeRepository.save(createAuthorizationCode());
    assertThat(codeRepository.count(), equalTo(1L));
    gc.clearExpiredAuthorizationCodes(1);
    assertThat(codeRepository.count(), equalTo(0L));
  }

  @Test
  @Transactional
  void clearExpiredTokensAndOrphanedAuthenticationHolder() {

    assertThat(accessTokenRepository.count(), equalTo(0L));
    assertThat(refreshTokenRepository.count(), equalTo(0L));
    assertThat(authenticationHolderRepository.count(), equalTo(0L));
    OAuth2AccessTokenEntity at = (OAuth2AccessTokenEntity) tokenService
      .createAccessToken(getOAuth2Authentication(Set.of("openid", "offline_access")));
    at.setExpiration(yesterday());
    accessTokenRepository.save(at);
    OAuth2RefreshTokenEntity rt = at.getRefreshToken();
    rt.setExpiration(yesterday());
    refreshTokenRepository.save(rt);
    assertThat(accessTokenRepository.count(), equalTo(1L));
    assertThat(refreshTokenRepository.count(), equalTo(1L));
    assertThat(authenticationHolderRepository.count(), equalTo(1L));
    gc.clearExpiredAccessTokens(1);
    assertThat(accessTokenRepository.count(), equalTo(0L));
    assertThat(refreshTokenRepository.count(), equalTo(1L));
    assertThat(authenticationHolderRepository.count(), equalTo(1L));
    gc.clearExpiredRefreshTokens(1);
    assertThat(refreshTokenRepository.count(), equalTo(0L));
    assertThat(authenticationHolderRepository.count(), equalTo(1L));
    gc.clearOrphanedAuthenticationHolder(1);
    assertThat(authenticationHolderRepository.count(), equalTo(0L));
  }

  @Test
  @Transactional
  void clearExpiredDeviceCodes() throws DeviceCodeCreationException {

    assertThat(deviceCodeRepository.count(), equalTo(0L));
    DeviceCode dc = codeService.createNewDeviceCode(Set.of("openid"),
        loadTestClient(DEVICE_CODE_CLIENT_ID), Map.of());
    dc.setExpiration(yesterday());
    deviceCodeRepository.save(dc);
    assertThat(deviceCodeRepository.count(), equalTo(1L));
    gc.clearExpiredDeviceCodes(1);
    assertThat(deviceCodeRepository.count(), equalTo(0L));
  }
}
