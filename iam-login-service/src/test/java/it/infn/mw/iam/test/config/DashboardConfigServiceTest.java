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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.dashboard.DashboardConfigService;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@ExtendWith(MockitoExtension.class)
class DashboardConfigServiceTest {

  @Mock
  IamClientRepository clientRepository;

  @Mock
  ClientManagementService clientService;

  @Mock
  ApplicationEventPublisher eventPublisher;

  @Mock
  IamProperties iamProperties;

  @Mock
  DashboardProperties dashboardProperties;

  @InjectMocks
  DashboardConfigService service;

  private ClientDetailsEntity clientWithSecret(String secret) {
    ClientDetailsEntity c = new ClientDetailsEntity();
    c.setClientSecret(secret);
    c.setScope(DashboardConfigService.DASHBOARD_SCOPES);
    c.setRedirectUris(Set.of("https://iam.example.org/ui/api/auth/oauth2/callback/indigo-iam"));
    c.setGrantTypes(Set.of("authorization_code", "refresh_token"));
    c.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    c.setCodeChallengeMethod(PKCEAlgorithm.S256);
    c.setActive(true);
    return c;
  }

  @Test
  void secretRotationOnlyUpdatesClientSecret() throws ParseException {

    String oldSecret = "oldSecretValue123456789012345678901234567890";
    String newSecret = "newSecretValue123456789012345678901234567890";

    ClientDetailsEntity client = clientWithSecret(oldSecret);

    when(clientRepository.findByClientId("dashboard-client")).thenReturn(Optional.of(client));

    when(iamProperties.getDashboard()).thenReturn(dashboardProperties);
    when(dashboardProperties.isEnabled()).thenReturn(true);
    when(dashboardProperties.getClientId()).thenReturn("dashboard-client");
    when(dashboardProperties.getClientSecret()).thenReturn(newSecret);
    when(iamProperties.getBaseUrl()).thenReturn("https://iam.example.org");

    service.init();

    ArgumentCaptor<ClientDetailsEntity> captor = ArgumentCaptor.forClass(ClientDetailsEntity.class);

    verify(clientRepository).save(captor.capture());

    ClientDetailsEntity saved = captor.getValue();

    assertEquals(newSecret, saved.getClientSecret());
    verify(eventPublisher).publishEvent(any());
  }

  @Test
  void noChangesDoesNotTriggerAnyUpdate() throws ParseException {

    String secret = "stableSecretValue123456789012345678901234567890";

    ClientDetailsEntity client = clientWithSecret(secret);

    when(clientRepository.findByClientId("dashboard-client")).thenReturn(Optional.of(client));

    when(iamProperties.getDashboard()).thenReturn(dashboardProperties);
    when(dashboardProperties.isEnabled()).thenReturn(true);
    when(dashboardProperties.getClientId()).thenReturn("dashboard-client");
    when(dashboardProperties.getClientSecret()).thenReturn(secret);
    when(iamProperties.getBaseUrl()).thenReturn("https://iam.example.org");

    service.init();

    verify(clientRepository, never()).save(any());
    verify(eventPublisher, never()).publishEvent(any());
  }

  @Test
  void configurationDriftTriggersFullClientUpdate() throws ParseException {

    ClientDetailsEntity client = clientWithSecret("secret");

    client.setRedirectUris(Set.of("https://wrong-uri"));

    when(clientRepository.findByClientId("dashboard-client")).thenReturn(Optional.of(client));

    when(iamProperties.getDashboard()).thenReturn(dashboardProperties);
    when(dashboardProperties.isEnabled()).thenReturn(true);
    when(dashboardProperties.getClientId()).thenReturn("dashboard-client");
    when(dashboardProperties.getClientSecret()).thenReturn("secret");
    when(iamProperties.getBaseUrl()).thenReturn("https://iam.example.org");

    service.init();

    verify(clientRepository).save(any());
    verify(eventPublisher).publishEvent(any());
  }

  @Test
  void missingClientCreatesNewOne() throws ParseException {

    when(clientRepository.findByClientId("dashboard-client")).thenReturn(Optional.empty());

    when(iamProperties.getDashboard()).thenReturn(dashboardProperties);
    when(dashboardProperties.isEnabled()).thenReturn(true);
    when(dashboardProperties.getClientId()).thenReturn("dashboard-client");
    when(dashboardProperties.getClientSecret()).thenReturn("secret");
    when(iamProperties.getBaseUrl()).thenReturn("https://iam.example.org");

    service.init();

    verify(clientService).saveNewClient(any());
    verify(clientRepository, never()).save(any());
  }
}
