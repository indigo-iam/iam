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

import java.time.Duration;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.exception.DeviceCodeCreationException;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.service.AuthenticationHolderEntityService;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
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
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SuppressWarnings("deprecation")
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(
    properties = {"iam.access_token.store_on_database=true", "scheduling.enabled=false"})
@Transactional
class GarbageCollectorIntegrationTests extends TokenGetterUtils {

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
  private IamOAuthAccessTokenRepository accessTokenRepository;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepository;

  @Autowired
  private DeviceCodeService codeService;

  @Autowired
  private IamDeviceCodeRepository deviceCodeRepository;

  @Autowired
  ClientDetailsEntityService clientDetailsService;

  @Autowired
  SecurityContextUtils sc;

  @Autowired
  MutableClock clock;

  private AuthorizationCodeEntity createAuthorizationCode() {
    OAuth2Authentication auth = getOAuth2Authentication();
    RandomValueStringGenerator generator = new RandomValueStringGenerator(22);
    AuthenticationHolderEntity authHolder = authenticationHolderService.create(auth);
    return new AuthorizationCodeEntity(generator.generate(), authHolder, clock.now());
  }

  private DeviceCode createDeviceCode(String clientId, Set<String> scopes)
      throws DeviceCodeCreationException {
    DeviceCode dc = codeService.createNewDeviceCode(scopes,
        clientDetailsService.loadClientByClientId(clientId), Map.of());
    dc.setExpiration(clock.now());
    return dc;
  }

  private OAuth2Authentication getOAuth2Authentication() {
    return getOAuth2Authentication(Set.of("openid"));
  }

  private OAuth2Authentication getOAuth2Authentication(Set<String> scopes) {
    return oauth2Authentication(clientDetailsService.loadClientByClientId(PASSWORD_CLIENT_ID),
        TEST_USERNAME, scopes.toArray(new String[0]));
  }

  @BeforeEach
  void cleanAll() {
    sc.cleanupSecurityContext();
    siteRepository.deleteAll();
    codeRepository.deleteAll();
    accessTokenRepository.deleteAll();
    refreshTokenRepository.deleteAll();
    deviceCodeRepository.deleteAll();
    authenticationHolderRepository.deleteAll();
  }

  @Test
  void clearExpiredApprovedSites() {

    assertThat(siteRepository.count(), equalTo(0L));
    approvedSiteService.createApprovedSite(PASSWORD_CLIENT_ID, TEST_USERNAME,
        Date.from(clock.daysBefore(2)), Set.of("openid"));
    assertThat(siteRepository.count(), equalTo(1L));
    clock.advance(Duration.ofDays(1));
    gc.clearExpiredApprovedSites(1);
    assertThat(siteRepository.count(), equalTo(0L));
  }

  @Test
  void clearExpiredAuthorizationCodes() {

    assertThat(codeRepository.count(), equalTo(0L));
    // Mitre's Authorization Code service is not using clock
    AuthorizationCodeEntity entity = codeRepository.save(createAuthorizationCode());
    entity.setExpiration(Date.from(clock.daysBefore(200)));
    codeRepository.save(entity);
    assertThat(codeRepository.count(), equalTo(1L));
    gc.clearExpiredAuthorizationCodes(1);
    assertThat(codeRepository.count(), equalTo(0L));
  }

  @Test
  void clearExpiredTokensAndOrphanedAuthenticationHolder() throws Exception {

    assertThat(accessTokenRepository.count(), equalTo(0L));
    assertThat(refreshTokenRepository.count(), equalTo(0L));
    assertThat(authenticationHolderRepository.count(), equalTo(0L));
    sc.useLocalTestUser();
    getPasswordToken(Set.of("openid", "offline_access"));
    assertThat(accessTokenRepository.count(), equalTo(1L));
    assertThat(refreshTokenRepository.count(), equalTo(1L));
    assertThat(authenticationHolderRepository.count(), equalTo(1L));
    clock.advance(Duration.ofDays(1));
    gc.clearExpiredAccessTokens(1);
    assertThat(accessTokenRepository.count(), equalTo(0L));
    assertThat(refreshTokenRepository.count(), equalTo(1L));
    assertThat(authenticationHolderRepository.count(), equalTo(1L));
    clock.advance(Duration.ofDays(30));
    gc.clearExpiredRefreshTokens(1);
    assertThat(refreshTokenRepository.count(), equalTo(0L));
    assertThat(authenticationHolderRepository.count(), equalTo(1L));
    gc.clearOrphanedAuthenticationHolder(1);
    assertThat(authenticationHolderRepository.count(), equalTo(0L));
  }

  @Test
  void clearExpiredDeviceCodes() throws DeviceCodeCreationException {

    assertThat(deviceCodeRepository.count(), equalTo(0L));
    deviceCodeRepository.save(createDeviceCode(DEVICE_CODE_CLIENT_ID, Set.of("openid")));
    assertThat(deviceCodeRepository.count(), equalTo(1L));
    clock.advance(Duration.ofDays(1));
    gc.clearExpiredDeviceCodes(1);
    assertThat(deviceCodeRepository.count(), equalTo(0L));
  }
}
