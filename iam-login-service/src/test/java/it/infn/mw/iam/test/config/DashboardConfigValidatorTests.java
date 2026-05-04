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
package it.infn.mw.iam.test.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.service.SystemScopeService;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.dashboard.DashboardConfigService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@ExtendWith(MockitoExtension.class)
class DashboardConfigServiceTests {

  private static final String BASE_URL = "https://iam.example.org";
  private static final String CLIENT_ID = "dashboard-client";
  private static final String CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz123456";
  private static final String NEW_SECRET = "123456abcdefghijklmnopqrstuvwxyz";
  private static final String CALLBACK = BASE_URL + "/ui/api/auth/oauth2/callback/indigo-iam";

  @Mock
  private IamClientRepository clientRepository;

  @Mock
  private DefaultClientManagementService clientService;

  @Mock
  private ApplicationEventPublisher eventPublisher;

  @Mock
  private IamProperties iamProperties;

  @Mock
  private IamProperties.DashboardProperties dashboardProperties;

  @InjectMocks
  private DashboardConfigService service;

  @BeforeEach
  void setup() {

    lenient().when(iamProperties.getDashboard()).thenReturn(dashboardProperties);
    lenient().when(iamProperties.getBaseUrl()).thenReturn(BASE_URL);

    lenient().when(dashboardProperties.isEnabled()).thenReturn(true);
    lenient().when(dashboardProperties.getClientId()).thenReturn(CLIENT_ID);
    lenient().when(dashboardProperties.getClientSecret()).thenReturn(CLIENT_SECRET);
  }

  @Test
  void initDoesNothingWhenDashboardDisabled() throws Exception {

    when(dashboardProperties.isEnabled()).thenReturn(false);

    service.init();

    verifyNoInteractions(clientRepository, clientService, eventPublisher);
  }

  @Test
  void initCreatesClientWhenMissing() throws Exception {

    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());

    service.init();

    verify(clientService).saveNewClient(any(RegisteredClientDTO.class));
    verifyNoInteractions(eventPublisher);
  }

  @Test
  void initDoesNothingWhenClientAlreadyConsistent() throws Exception {

    ClientDetailsEntity client = validClient();

    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));

    service.init();

    verify(clientRepository, never()).save(any());
    verify(eventPublisher, never()).publishEvent(any());
  }

  @Test
  void initRotatesSecretWhenSecretChanged() throws Exception {

    ClientDetailsEntity client = validClient();
    client.setClientSecret(NEW_SECRET);

    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));

    service.init();

    verify(clientRepository).save(client);
    verify(eventPublisher).publishEvent(any(ClientUpdatedEvent.class));

    assertEquals(CLIENT_SECRET, client.getClientSecret());
  }

  @Test
  void initRepairsStructuralDrift() throws Exception {

    ClientDetailsEntity client = validClient();
    client.setRedirectUris(Set.of("https://wrong.example.org"));

    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));

    service.init();

    verify(clientRepository).save(client);
    verify(eventPublisher).publishEvent(any(ClientUpdatedEvent.class));

    assertEquals(Set.of(CALLBACK), client.getRedirectUris());
  }

  @Test
  void initRepairsDriftAndRotatesSecret() throws Exception {

    ClientDetailsEntity client = validClient();
    client.setClientSecret(NEW_SECRET);
    client.setActive(false);

    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));

    service.init();

    verify(clientRepository).save(client);
    verify(eventPublisher).publishEvent(any(ClientUpdatedEvent.class));

    assertEquals(CLIENT_SECRET, client.getClientSecret());
    assertTrue(client.isActive());
  }

  @Test
  void detectsSecretRotation() {

    ClientDetailsEntity client = validClient();
    client.setClientSecret("different-secret");

    assertTrue(DashboardConfigService.hasSecretRotation(client, CLIENT_SECRET));
  }

  @Test
  void detectsNoSecretRotation() {

    ClientDetailsEntity client = validClient();

    assertFalse(DashboardConfigService.hasSecretRotation(client, CLIENT_SECRET));
  }

  @Test
  void detectsConfigurationDrift() {

    ClientDetailsEntity client = validClient();
    client.setActive(false);

    assertTrue(DashboardConfigService.hasConfigurationDrift(client, CALLBACK));
  }

  @Test
  void detectsNoConfigurationDrift() {

    ClientDetailsEntity client = validClient();

    assertFalse(DashboardConfigService.hasConfigurationDrift(client, CALLBACK));
  }

  private ClientDetailsEntity validClient() {

    ClientDetailsEntity client = new ClientDetailsEntity();

    client.setClientId(CLIENT_ID);
    client.setClientSecret(CLIENT_SECRET);
    client.setActive(true);
    client.setScope(Set.of(SystemScopeService.OPENID_SCOPE, SystemScopeService.OFFLINE_ACCESS,
        "email", "profile", "iam:admin.read", "iam:admin.write", "scim:read", "scim:write"));
    client.setRedirectUris(Set.of(CALLBACK));
    client.setGrantTypes(Set.of(AuthorizationGrantType.CODE.getGrantType(),
        AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
    client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);

    return client;
  }
}
