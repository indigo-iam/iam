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
package it.infn.mw.iam.test.openid_federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationServiceException;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.openid_federation.FederatedOpRegistrationService;
import it.infn.mw.iam.api.openid_federation.FederationClientConfigurationService;
import it.infn.mw.iam.authn.oidc.exception.ClientConfigurationNotFoundException;
import it.infn.mw.iam.authn.oidc.service.CompositeClientConfigurationService;
import it.infn.mw.iam.authn.oidc.service.SafeStaticClientConfigurationService;
import it.infn.mw.iam.core.oidc.FederationException;
import it.infn.mw.iam.persistence.repository.IamFederatedClientRepository;

@ExtendWith(MockitoExtension.class)
class ClientConfigurationServiceTests {

  @Mock
  IamFederatedClientRepository clientRepo;

  @Mock
  FederatedOpRegistrationService federationRegistrationService;

  ClientConfigurationService service;

  FederationClientConfigurationService federationService;

  @BeforeEach
  void setup() {
    federationService = new FederationClientConfigurationService(clientRepo,
        federationRegistrationService, Clock.systemUTC());
  }

  private RegisteredClientDTO mockDto() {
    RegisteredClientDTO dto = new RegisteredClientDTO();
    dto.setClientId("federated-client");
    dto.setClientSecret("secret");

    dto.setRedirectUris(Set.of("https://client/callback"));
    dto.setScope(Set.of("openid"));

    return dto;
  }

  @Test
  void returnStaticClientWhenIssuerIsConfigured() {
    String issuer = "https://static.example.org";

    RegisteredClient staticClient = new RegisteredClient();
    staticClient.setClientId("static-client");

    Map<String, RegisteredClient> clients = Map.of(issuer, staticClient);

    ClientConfigurationService staticService = new SafeStaticClientConfigurationService(clients);

    service = new CompositeClientConfigurationService(List.of(staticService, federationService));

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer(issuer);

    RegisteredClient result = service.getClientConfiguration(sc);

    assertThat(result.getClientId()).isEqualTo("static-client");

    verifyNoInteractions(federationRegistrationService);
  }

  @Test
  void fallBackToFederationWhenStaticMissing() throws Exception {
    String issuer = "https://federated.example.org";

    when(federationRegistrationService.registerOp(eq(issuer), any())).thenReturn(mockDto());

    service = new CompositeClientConfigurationService(List.of(federationService));

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer(issuer);

    RegisteredClient result = service.getClientConfiguration(sc);

    assertThat(result).isNotNull();
    assertThat(result.getClientId()).isEqualTo("federated-client");

    verify(federationRegistrationService).registerOp(eq(issuer), any());
  }

  @Test
  void throwExceptionWhenFederationFails() throws Exception {
    String issuer = "https://federated.example.org";

    when(federationRegistrationService.registerOp(eq(issuer), any()))
      .thenThrow(FederationException.invalidRequest("error"));

    service = new CompositeClientConfigurationService(List.of(federationService));

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer(issuer);

    assertThatThrownBy(() -> service.getClientConfiguration(sc))
      .isInstanceOf(AuthenticationServiceException.class);
  }

  @Test
  void throwExceptionWhenIssuerIsNotConfigured() {
    service = new SafeStaticClientConfigurationService(Collections.emptyMap());

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer("https://unknown.org");

    assertThatThrownBy(() -> service.getClientConfiguration(sc))
      .isInstanceOf(ClientConfigurationNotFoundException.class)
      .hasMessageContaining("No static client for issuer");
  }

  @Test
  void throwExceptionWhenNoConfigurationExists() {
    service = new CompositeClientConfigurationService(List.of());

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer("https://unknown.example.org");

    assertThatThrownBy(() -> service.getClientConfiguration(sc))
      .isInstanceOf(ClientConfigurationNotFoundException.class);
  }
}
