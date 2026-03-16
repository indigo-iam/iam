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
package it.infn.mw.iam.test.dashboard;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.PKCEAlgorithm;

import java.util.Set;

import javax.transaction.Transactional;

import com.google.common.collect.Sets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import it.infn.mw.iam.dashboard.DashboardConfigService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;

@SpringBootTest(classes = { IamLoginService.class })
@Transactional
class DashboardConfigServiceTest {

  private static final String CLIENT_ID = "dashboard-client";
  private static final String CLIENT_SECRET = "secret";
  private static final String BASE_URL = "http://localhost:8080";
  private static final Set<String> SCOPES = Sets.newHashSet("openid", "profile", "email", "iam:admin.read",
      "iam:admin.write", "scim:read", "scim:write", "offline_access");
  private static final Set<String> AUTH_GRAND_TYPE = Set.of(AuthorizationGrantType.CODE.getGrantType(),
      AuthorizationGrantType.REFRESH_TOKEN.getGrantType());

  private ClientDetailsEntity clientDashboard;

  @Autowired
  private DashboardConfigService dashboardConfigService;

  @Autowired
  private IamClientRepository iamClientDetailsRepository;

  @BeforeEach
  void setUp() {
    clientDashboard = new ClientDetailsEntity();
    clientDashboard.setClientId(CLIENT_ID);
    clientDashboard.setClientSecret(CLIENT_SECRET);
    clientDashboard.setScope(SCOPES);
    clientDashboard.setGrantTypes(AUTH_GRAND_TYPE);
    clientDashboard.setRedirectUris(Set.of("http://localhost:8080/api/auth/oauth2/callback/indigo-iam"));
    clientDashboard.setCodeChallengeMethod(PKCEAlgorithm.S256);
    clientDashboard.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    iamClientDetailsRepository.save(clientDashboard);
  }

  @AfterEach
  void tearDown() {
    iamClientDetailsRepository.delete(clientDashboard);
  }

  @Test
  void testCheckRecordConfiguration() {
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, SCOPES);

    assertEquals(true, dashboardConfigService.checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));
  }

  @Test
  void testFailCheckRecordScopeConfiguration() {
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE,
        Sets.newHashSet("openid"));

    assertEquals(false, dashboardConfigService.checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));
  }

  @Test
  void testFailCheckRecordClientSecretConfiguration() {
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, SCOPES);

    assertEquals(false, dashboardConfigService.checkRecordConfiguration(client, "test_secret", BASE_URL));
  }

  @Test
  void testInitDashboardClient() {
    DashboardProperties properties = new DashboardProperties();
    properties.setClientId(CLIENT_ID);
    properties.setClientSecret(CLIENT_SECRET);

    assertEquals(true, dashboardConfigService.initDashboardClient(properties, BASE_URL));
  }

  @Test
  void testInitDashboardClientInsertDashboard() {
    assertThat(iamClientDetailsRepository.findByClientId(CLIENT_ID + "-new").isPresent(), is(false));

    DashboardProperties properties = new DashboardProperties();
    properties.setClientId(CLIENT_ID + "-new");
    properties.setClientSecret(CLIENT_SECRET);

    assertEquals(true, dashboardConfigService.initDashboardClient(properties, BASE_URL));

    iamClientDetailsRepository.findByClientId(CLIENT_ID + "-new").ifPresentOrElse(c -> {
      assertEquals(CLIENT_ID + "-new", c.getClientId());
      assertEquals(clientDashboard.getScope(), c.getScope());
    }, () -> {
      throw new AssertionError("Client not found");
    });
  }

  @Test
  void testInitDashboardClientUpdateDashboard() {
    assertThat(iamClientDetailsRepository.findByClientId(CLIENT_ID + "-new").isPresent(), is(false));

    DashboardProperties properties = new DashboardProperties();
    properties.setClientId(CLIENT_ID);
    properties.setClientSecret(CLIENT_SECRET);

    assertEquals(true, dashboardConfigService.initDashboardClient(properties, BASE_URL));

    iamClientDetailsRepository.findByClientId(CLIENT_ID).ifPresentOrElse(c -> {
      assertEquals(CLIENT_ID, c.getClientId());
      assertEquals(clientDashboard.getScope(), c.getScope());
    }, () -> {
      throw new AssertionError("Client not found");
    });
  }

  private ClientDetailsEntity createClientDashboard(String clientId, String clientSecret,
      String redirectUris, Set<String> grantTypes, Set<String> scopes) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(clientId);
    client.setClientSecret(clientSecret);
    client.setScope(scopes);
    client.setGrantTypes(grantTypes);
    client.setRedirectUris(Set.of(redirectUris));
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    return client;
  }
}
