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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.mitre.oauth2.model.PKCEAlgorithm;

import java.text.ParseException;
import java.util.Optional;
import java.util.Set;

import com.google.common.collect.Sets;

import it.infn.mw.iam.dashboard.DashboardConfigService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;

@ExtendWith(MockitoExtension.class)
class DashboardConfigServiceTest {

  private static final String CLIENT_ID = "dashboard-client";
  private static final String CLIENT_SECRET = "dashboard-client-secret-01234567890";
  private static final String BASE_URL = "http://localhost:8080";
  private static final Set<String> SCOPES = Sets.newHashSet("openid", "profile", "email", "iam:admin.read",
      "iam:admin.write", "scim:read", "scim:write", "offline_access");
  private static final Set<String> AUTH_GRAND_TYPE = Set.of(AuthorizationGrantType.CODE.getGrantType(),
      AuthorizationGrantType.REFRESH_TOKEN.getGrantType());

  @Mock
  IamClientRepository clientRepository;

  @Mock
  DefaultClientManagementService clientService;

  @Mock
  ApplicationEventPublisher eventPublisher;

  @Mock
  IamProperties iamProperties;

  private DashboardConfigService getService() {
    return new DashboardConfigService(clientRepository, clientService, eventPublisher, iamProperties);
  }

  @Test
  void testCheckRecordConfiguration() {
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, SCOPES,
        true);

    assertEquals(true, getService().checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));
  }

  @Test
  void testFailCheckRecordWithWrongConfigurations() {
    Set<String> scopesWithoutRequired = Sets.newHashSet("FAKE_SCOPE");
    ClientDetailsEntity client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE,
        scopesWithoutRequired, true);
    assertEquals(false, getService().checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));

    scopesWithoutRequired = Sets.newHashSet("openid");
    client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, scopesWithoutRequired, true);
    assertEquals(false, getService().checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));

    client = createClientDashboard(CLIENT_ID, "test_secret", BASE_URL, AUTH_GRAND_TYPE, SCOPES, true);
    assertEquals(false, getService().checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));

    client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, "https://fake.url", AUTH_GRAND_TYPE, SCOPES, true);
    assertEquals(false, getService().checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));

    client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL,
        Set.of(AuthorizationGrantType.CODE.getGrantType()),
        SCOPES, true);
    assertEquals(false, getService().checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));

    client = createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, SCOPES, false);
    assertEquals(false, getService().checkRecordConfiguration(client, CLIENT_SECRET, BASE_URL));

  }

  @Test
  void testInit() {
    ClientDetailsEntity dashboard = setClientDashboard();
    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(dashboard));

    mockDashboardProperties(true, CLIENT_ID, CLIENT_SECRET);
    assertDoesNotThrow(() -> getService().init());
  }

  @Test
  void testInitInsertNewDashboardClient() throws ParseException {
    String newClientId = "new-" + CLIENT_ID;
    mockDashboardProperties(true, newClientId, CLIENT_SECRET);

    assertThat(clientRepository.findByClientId(newClientId).isPresent(), is(false));
    assertDoesNotThrow(() -> getService().init());
    verify(clientService, times(1)).saveNewClient(any());
    verify(clientRepository, times(0)).save(any());
  }

  @Test
  void testInitUpdateDashboard() throws ParseException {
    String newClientId = "new-" + CLIENT_ID;
    mockDashboardProperties(true, CLIENT_ID, CLIENT_SECRET);
    ClientDetailsEntity dashboard = setClientDashboard();
    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(dashboard));

    assertThat(clientRepository.findByClientId(newClientId).isPresent(), is(false));
    assertDoesNotThrow(() -> getService().init());
    verify(clientService, times(0)).saveNewClient(any());
    verify(clientRepository, times(1)).save(any());
  }

  private ClientDetailsEntity createClientDashboard(String clientId, String clientSecret,
      String redirectUris, Set<String> grantTypes, Set<String> scopes, boolean isActive) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(clientId);
    client.setClientSecret(clientSecret);
    client.setScope(scopes);
    client.setGrantTypes(grantTypes);
    client.setRedirectUris(Set.of(redirectUris));
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    client.setActive(isActive);
    return client;
  }

  private ClientDetailsEntity setClientDashboard() {
    return createClientDashboard(CLIENT_ID, CLIENT_SECRET, BASE_URL, AUTH_GRAND_TYPE, SCOPES, true);
  }

  private void mockDashboardProperties(boolean isENabled, String clientId, String secret) {
    DashboardProperties properties = Mockito.mock(DashboardProperties.class);
    lenient().when(properties.isEnabled()).thenReturn(isENabled);
    lenient().when(properties.getClientId()).thenReturn(clientId);
    lenient().when(properties.getClientSecret()).thenReturn(secret);
    when(iamProperties.getDashboard()).thenReturn(properties);
  }
}
