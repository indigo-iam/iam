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
package it.infn.mw.iam.test.client.last_used;

import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.persistence.model.ClientLastUsedEntity;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SuppressWarnings("deprecation")
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ClientLastUsedTests extends TokenGetterUtils {

  static final String TEST_347_USER = "test_347";
  static final String SCOPES = "offline_access";

  @Autowired
  IamProperties iamProperties;

  @Autowired
  ClientService clientDetailsService;

  @Autowired
  AuthorizationServerTokenServices tokenService;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  LocalDate now;

  @BeforeEach
  void init() {
    context.cleanupSecurityContext();
    now = LocalDate.ofInstant(clock.instant(), ZoneId.of("UTC"));
  }

  @Test
  void testClientLastUsedCreationOnTokenCreation() throws Exception {

    // Initially, the last used is null
    assertNotYetUsed(LOOKUP_CLIENT_ID);

    context.useLocalUser(LOOKUP_CLIENT_ID, TEST_347_USER, new String[] {"ROLE_USER"});

    // When the last used date is not tracked, it is not updated and remains null
    iamProperties.getClient().setTrackLastUsed(false);
    assertNotNull(getPasswordToken(LOOKUP_CLIENT_ID, LOOKUP_CLIENT_SECRET, TEST_347_USER,
        "password", "openid").accessToken());
    assertNotYetUsed(LOOKUP_CLIENT_ID);

    // When the last used date is tracked, it is created with the current date
    iamProperties.getClient().setTrackLastUsed(true);
    assertNotNull(getPasswordToken(LOOKUP_CLIENT_ID, LOOKUP_CLIENT_SECRET, TEST_347_USER,
        "password", "openid").accessToken());
    assertLastUsedIs(LOOKUP_CLIENT_ID, now);
  }

  @Test
  void testLastUsedUpdateOnTokenCreation() throws Exception {

    iamProperties.getClient().setTrackLastUsed(true);

    // Initially, the last used date is set to the value created through a test migration
    assertLastUsedIs(POST_CLIENT_ID, LocalDate.of(1994, 3, 19));

    context.useLocalUser(POST_CLIENT_ID, TEST_347_USER, new String[] {"ROLE_USER"});
    // After creating a token, the last used date is updated
    assertNotNull(
        getPasswordToken(POST_CLIENT_ID, POST_CLIENT_SECRET, TEST_347_USER, "password", "openid")
          .accessToken());
    assertLastUsedIs(POST_CLIENT_ID, now);
  }

  @Test
  void testClientLastUsedCreationOnTokenRefresh() throws Exception {

    // Initially, the last used is null
    assertNotYetUsed(LOOKUP_CLIENT_ID);

    iamProperties.getClient().setTrackLastUsed(false);

    assertTrue(clientDetailsService.findClientByClientId(LOOKUP_CLIENT_ID).get().isAllowRefresh());

    context.useLocalUser(LOOKUP_CLIENT_ID, TEST_347_USER, new String[] {"ROLE_USER"});
    // Initially, the last used date is null
    String refreshToken = getPasswordToken(LOOKUP_CLIENT_ID, LOOKUP_CLIENT_SECRET, TEST_347_USER,
        "password", "openid offline_access").refreshToken();
    assertNotNull(refreshToken);
    assertNotYetUsed(LOOKUP_CLIENT_ID);

    // After refreshing the access token, the last used date is created with the
    // current date
    iamProperties.getClient().setTrackLastUsed(true);
    TokenRequest tokenRequest =
        new TokenRequest(emptyMap(), LOOKUP_CLIENT_ID, Collections.emptySet(), "");
    tokenService.refreshAccessToken(refreshToken, tokenRequest);
    assertLastUsedIs(LOOKUP_CLIENT_ID, now);
  }

  @Test
  void testClientLastUsedUpdateOnTokenRefresh() throws Exception {

    iamProperties.getClient().setTrackLastUsed(false);

    // Get a client with a default last used date and able to generate refresh tokens
    assertTrue(clientDetailsService.findClientByClientId(LOOKUP_CLIENT_ID).get().isAllowRefresh());
    // Initially, the last used date is set to the default value
    assertLastUsedIs(TEST_CLIENT_ID, LocalDate.of(1994, 3, 21));

    context.useLocalUser(TEST_CLIENT_ID, TEST_347_USER, new String[] {"ROLE_USER"});
    // After creating an access token, the last used date is not updated
    String refreshToken = getPasswordToken(TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_347_USER,
        "password", "openid offline_access").refreshToken();
    assertNotNull(refreshToken);
    assertLastUsedIs(TEST_CLIENT_ID, LocalDate.of(1994, 3, 21));

    // After refreshing the access token, the last used date is updated
    iamProperties.getClient().setTrackLastUsed(true);
    TokenRequest tokenRequest =
        new TokenRequest(emptyMap(), TEST_CLIENT_ID, Collections.emptySet(), "");
    tokenService.refreshAccessToken(refreshToken, tokenRequest);
    assertLastUsedIs(TEST_CLIENT_ID, now);
  }

  private void assertLastUsedIs(String clientId, LocalDate expected) {

    ClientLastUsedEntity lastUsedEntity =
        clientDetailsService.findClientByClientId(clientId).get().getClientLastUsed();
    assertNotNull(lastUsedEntity);
    assertEquals(expected, lastUsedEntity.getLastUsed());
  }

  private void assertNotYetUsed(String clientId) {

    assertNull(clientDetailsService.findClientByClientId(clientId).get().getClientLastUsed());
  }
}
