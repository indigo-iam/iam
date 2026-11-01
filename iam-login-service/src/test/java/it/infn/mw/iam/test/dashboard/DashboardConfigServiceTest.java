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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.service.ClientUtils;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;
import it.infn.mw.iam.dashboard.DashboardConfigService;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@ExtendWith(MockitoExtension.class)
class DashboardConfigServiceTest {

  private static final String CLIENT_ID = "dashboard-client";
  private static final String CLIENT_SECRET = "dashboard-client-secret-01234567890";
  private static final String BASE_URL = "https://iam.example.org";
  private static final String REDIRECT_URI = BASE_URL + DashboardConfigService.DASHBOARD_CALLBACK;

  private static final Set<String> GRANT_TYPES = Set.of("authorization_code", "refresh_token");

  @Mock
  ClientService clientService;

  @Mock
  ClientUtils clientUtils;

  @Mock
  ApplicationEventPublisher eventPublisher;

  @Mock
  IamProperties iamProperties;

  @Mock
  DashboardProperties dashboardProperties;

  IamSha256PasswordEncoder encoder;
  DashboardConfigService service;

  @BeforeEach
  void setUp() {
    encoder = new IamSha256PasswordEncoder();
    service = new DashboardConfigService(clientService, clientUtils, encoder, eventPublisher,
        iamProperties);
  }

  @Test
  void disabledDashboardDoesNothing() {
    when(iamProperties.getDashboard()).thenReturn(dashboardProperties);
    when(dashboardProperties.isEnabled()).thenReturn(false);

    service.ensureDashboardClientConfigured();

    verifyNoInteractions(clientService, clientUtils, eventPublisher);
  }

  @Test
  void unchangedConfigurationDoesNotTriggerUpdate() {
    configureDashboard(CLIENT_SECRET);
    when(clientService.findClientByClientId(CLIENT_ID))
      .thenReturn(Optional.of(existingClient(CLIENT_SECRET)));

    service.ensureDashboardClientConfigured();

    verify(clientService, never()).saveNewClient(any());
    verify(clientService, never()).updateClient(any());
    verifyNoInteractions(clientUtils, eventPublisher);
  }

  @Test
  void missingClientCreatesNewOne() {
    configureDashboard(CLIENT_SECRET);
    when(clientService.findClientByClientId(CLIENT_ID)).thenReturn(Optional.empty());

    service.ensureDashboardClientConfigured();

    ArgumentCaptor<ClientDetailsEntity> captor = ArgumentCaptor.forClass(ClientDetailsEntity.class);

    verify(clientService).saveNewClient(captor.capture());

    ClientDetailsEntity created = captor.getValue();
    assertEquals(CLIENT_ID, created.getClientId());
    assertEquals(DashboardConfigService.DASHBOARD_CLIENT_NAME, created.getClientName());
    assertEquals(Integer.valueOf(3600), created.getAccessTokenValiditySeconds());
    assertEquals(ClientAuthMethod.SECRET_BASIC, created.getTokenEndpointAuthMethod());
    assertEquals(2, created.getGrantTypes().size());
    assertTrue(created.getGrantTypes()
      .containsAll(Set.of(AuthorizationGrantType.CODE.getGrantType(),
          AuthorizationGrantType.REFRESH_TOKEN.getGrantType())));
    assertEquals(PKCEAlgorithm.S256, created.getCodeChallengeMethod());
    assertEquals(DashboardConfigService.DASHBOARD_SCOPES.size(), created.getScope().size());
    assertTrue(created.getScope().containsAll(DashboardConfigService.DASHBOARD_SCOPES));
    assertEquals(1, created.getRedirectUris().size());
    assertTrue(created.getRedirectUris().contains(BASE_URL + DashboardConfigService.DASHBOARD_CALLBACK));
    assertFalse(created.isDynamicallyRegistered());
    assertTrue(created.isActive());
    assertExpectedConfiguration(created, CLIENT_SECRET);

    verify(clientUtils).setupClientDefaults(created);
    verify(clientService, never()).updateClient(any());
    verifyNoInteractions(eventPublisher);
  }

  @Test
  void secretRotationUpdatesStoredHashAndPreservesOtherSettings() {
    String newSecret = "new-dashboard-secret-01234567890";
    ClientDetailsEntity client = existingClient(CLIENT_SECRET);

    configureDashboard(newSecret);
    mockExistingClientForUpdate(client);

    service.ensureDashboardClientConfigured();

    ArgumentCaptor<ClientDetailsEntity> captor = ArgumentCaptor.forClass(ClientDetailsEntity.class);

    verify(clientService).updateClient(captor.capture());

    ClientDetailsEntity updated = captor.getValue();
    assertExpectedConfiguration(updated, newSecret);
    assertEquals(CLIENT_ID, updated.getClientId());
    assertEquals("Existing dashboard", updated.getClientName());
    assertEquals(Integer.valueOf(7200), updated.getAccessTokenValiditySeconds());

    verify(clientService, never()).saveNewClient(any());
    verify(eventPublisher).publishEvent(any(ClientUpdatedEvent.class));
  }

  @ParameterizedTest
  @MethodSource("configurationDrifts")
  void configurationDriftIsRepaired(Consumer<ClientDetailsEntity> drift) {
    ClientDetailsEntity client = existingClient(CLIENT_SECRET);
    drift.accept(client);

    configureDashboard(CLIENT_SECRET);
    mockExistingClientForUpdate(client);

    service.ensureDashboardClientConfigured();

    ArgumentCaptor<ClientDetailsEntity> captor = ArgumentCaptor.forClass(ClientDetailsEntity.class);

    verify(clientService).updateClient(captor.capture());
    assertExpectedConfiguration(captor.getValue(), CLIENT_SECRET);

    verify(clientService, never()).saveNewClient(any());
    verify(eventPublisher).publishEvent(any(ClientUpdatedEvent.class));
  }

  @Test
  void configurationDriftAndSecretRotationAreRepairedTogether() {
    String newSecret = "new-dashboard-secret-01234567890";
    ClientDetailsEntity client = existingClient(CLIENT_SECRET);
    client.setRedirectUris(Set.of("https://wrong.example.org"));
    client.setActive(false);

    configureDashboard(newSecret);
    mockExistingClientForUpdate(client);

    service.ensureDashboardClientConfigured();

    ArgumentCaptor<ClientDetailsEntity> captor = ArgumentCaptor.forClass(ClientDetailsEntity.class);

    verify(clientService).updateClient(captor.capture());

    ClientDetailsEntity updated = captor.getValue();
    assertExpectedConfiguration(updated, newSecret);
    assertEquals(CLIENT_ID, updated.getClientId());
    assertEquals("Existing dashboard", updated.getClientName());
    assertEquals(Integer.valueOf(7200), updated.getAccessTokenValiditySeconds());

    verify(clientService, never()).saveNewClient(any());
    verifyNoInteractions(clientUtils);
    verify(eventPublisher).publishEvent(any(ClientUpdatedEvent.class));
  }

  @Test
  void additionalScopesDoNotTriggerUpdate() {
    ClientDetailsEntity client = existingClient(CLIENT_SECRET);
    Set<String> scopes = new HashSet<>(DashboardConfigService.DASHBOARD_SCOPES);
    scopes.add("additional-scope");
    client.setScope(scopes);

    configureDashboard(CLIENT_SECRET);
    when(clientService.findClientByClientId(CLIENT_ID)).thenReturn(Optional.of(client));

    service.ensureDashboardClientConfigured();

    verify(clientService, never()).saveNewClient(any());
    verify(clientService, never()).updateClient(any());
    verifyNoInteractions(clientUtils, eventPublisher);
    assertEquals(scopes, client.getScope());
  }

  private static Stream<Consumer<ClientDetailsEntity>> configurationDrifts() {
    return Stream.<Consumer<ClientDetailsEntity>>of(client -> client.setScope(null),
        client -> client.setScope(Set.of("FAKE_SCOPE")),
        client -> client.setScope(Set.of("openid")),
        client -> client.setRedirectUris(Set.of("https://wrong.example.org")),
        client -> client.setGrantTypes(Set.of("authorization_code")),
        client -> client.setTokenEndpointAuthMethod(null),
        client -> client.setCodeChallengeMethod(null), client -> client.setActive(false));
  }

  private ClientDetailsEntity existingClient(String plainSecret) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(CLIENT_ID);
    client.setClientName("Existing dashboard");
    client.setClientSecret(encoder.encode(plainSecret));
    client.setScope(DashboardConfigService.DASHBOARD_SCOPES);
    client.setRedirectUris(Set.of(REDIRECT_URI));
    client.setGrantTypes(GRANT_TYPES);
    client.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setAccessTokenValiditySeconds(7200);
    client.setActive(true);
    return client;
  }

  private void configureDashboard(String plainSecret) {
    when(iamProperties.getDashboard()).thenReturn(dashboardProperties);
    when(dashboardProperties.isEnabled()).thenReturn(true);
    when(dashboardProperties.getClientId()).thenReturn(CLIENT_ID);
    when(dashboardProperties.getClientSecret()).thenReturn(plainSecret);
    when(iamProperties.getBaseUrl()).thenReturn(BASE_URL);
  }

  private void mockExistingClientForUpdate(ClientDetailsEntity client) {
    when(clientService.findClientByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
    when(clientService.updateClient(any(ClientDetailsEntity.class)))
      .thenAnswer(invocation -> invocation.getArgument(0));
  }

  private void assertExpectedConfiguration(ClientDetailsEntity client, String plainSecret) {
    assertEquals(encoder.encode(plainSecret), client.getClientSecret());
    assertEquals(DashboardConfigService.DASHBOARD_SCOPES, client.getScope());
    assertEquals(Set.of(REDIRECT_URI), client.getRedirectUris());
    assertEquals(GRANT_TYPES, client.getGrantTypes());
    assertEquals(ClientAuthMethod.SECRET_BASIC, client.getTokenEndpointAuthMethod());
    assertEquals(PKCEAlgorithm.S256, client.getCodeChallengeMethod());
    assertTrue(client.isActive());
  }
}
