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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationServiceException;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.openid_federation.FederatedOpRegistrationService;
import it.infn.mw.iam.authn.oidc.ClientConfigurationService;
import it.infn.mw.iam.authn.oidc.OpenIdFederationClientConfigurationService;
import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.core.oidc.FederationException;
import it.infn.mw.iam.persistence.repository.IamFederatedClientRepository;

@ExtendWith(MockitoExtension.class)
class ClientConfigurationServiceTests {

  @Mock
  IamFederatedClientRepository clientRepo;

  @Mock
  FederatedOpRegistrationService federationRegistrationService;

  @Mock
  OidcProviderProperties oidcProperties;

  ClientConfigurationService service;

  @BeforeEach
  void setup() {
    service = new OpenIdFederationClientConfigurationService(oidcProperties, Clock.systemUTC(),
        clientRepo, federationRegistrationService);
  }

  private RegisteredClientDTO mockDto(String clientId) {

    RegisteredClientDTO dto = new RegisteredClientDTO();
    dto.setClientId(clientId);
    dto.setClientSecret("secret");
    dto.setRedirectUris(Set.of("https://client/callback"));
    dto.setScope(Set.of("openid"));
    return dto;
  }

  private OidcProvider mockProvider(String issuer, OidcClient client) {

    OidcProvider staticProvider = new OidcProvider();
    staticProvider.setIssuer(issuer);
    staticProvider.setClient(client);
    return staticProvider;
  }

  private OidcClient mockClient(String clientId) {

    return new OidcClient(clientId, "secret", "openid", null, null, AuthMethod.SECRET_BASIC);
  }

  @Test
  void returnStaticClientWhenIssuerIsConfigured() {

    String issuer = "https://static.example.org";
    String clientId = "static-client";

    when(oidcProperties.getProviders())
      .thenReturn(List.of(mockProvider(issuer, mockClient(clientId))));

    Optional<OidcClient> result = service.getClientConfiguration(issuer);

    assertEquals(clientId, result.get().clientId());
    verifyNoInteractions(federationRegistrationService);
  }

  @Test
  void fallBackToFederationWhenStaticMissing() throws Exception {

    when(oidcProperties.getProviders()).thenReturn(List.of());

    String issuer = "https://federated.example.org";
    String clientId = "federated-client";

    when(federationRegistrationService.registerOp(eq(issuer), any())).thenReturn(mockDto(clientId));

    Optional<OidcClient> result = service.getClientConfiguration(issuer);

    assertEquals(clientId, result.get().clientId());

    verify(federationRegistrationService).registerOp(eq(issuer), any());
  }

  @Test
  void throwExceptionWhenFederationFails() throws Exception {

    when(oidcProperties.getProviders()).thenReturn(List.of());

    String issuer = "https://federated.example.org";

    when(federationRegistrationService.registerOp(eq(issuer), any()))
      .thenThrow(FederationException.invalidRequest("error"));

    assertThatThrownBy(() -> service.getClientConfiguration(issuer))
      .isInstanceOf(AuthenticationServiceException.class);
  }
}
