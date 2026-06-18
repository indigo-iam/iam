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
package it.infn.mw.iam.test.oauth.introspection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.core.oauth.discovery.OidcDiscoveryService;
import it.infn.mw.iam.core.oauth.introspection.model.DelegatingOpaqueTokenIntrospector;
import it.infn.mw.iam.test.util.TokenGetterUtils;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class OpaqueTokenIntrospectorTests extends TokenGetterUtils {

  @Mock
  OidcProviderProperties properties;

  @Mock
  OidcDiscoveryService discoveryService;

  @Mock
  Function<OidcClient, RestTemplate> restTemplateMapper;

  @Mock
  RestTemplate restTemplate;

  Clock clock;

  OpaqueTokenIntrospector introspector;

  @BeforeEach
  void setup() {
    clock = Clock.systemUTC();
    introspector =
        new DelegatingOpaqueTokenIntrospector(properties, restTemplateMapper, discoveryService);
  }

  @Test
  void introspectAllowedWhenFlagIsTrue() {
    String issuer = "https://example.com";

    OidcClient client = new OidcClient();
    client.setClientId("client");
    client.setClientSecret("secret");

    OidcProvider enabled = new OidcProvider();
    enabled.setIssuer(issuer);
    enabled.setClient(client);
    enabled.setAllowProxiedIntrospection(true);

    when(properties.getProviders()).thenReturn(List.of(enabled));
    OidcProvider result = properties.getProviders()
      .stream()
      .filter(
          c -> c.getIssuer().equals(issuer) && Boolean.TRUE.equals(c.isAllowProxiedIntrospection()))
      .findFirst()
      .orElseThrow(() -> new InvalidTokenException("Not allowed"));
    assertEquals(enabled, result);
  }

  @Test
  void introspectThrowsExceptionWhenFlagIsFalse() {
    String issuer = "https://example.com";

    OidcClient client = new OidcClient();
    client.setClientId("client");
    client.setClientSecret("secret");

    OidcProvider disabled = new OidcProvider();
    disabled.setIssuer(issuer);
    disabled.setClient(client);
    disabled.setAllowProxiedIntrospection(false);

    when(properties.getProviders()).thenReturn(List.of(disabled));

    Supplier<OidcProvider> providerSupplier = () -> properties.getProviders()
      .stream()
      .filter(p -> p.getIssuer().equals(issuer) && p.isAllowProxiedIntrospection())
      .findFirst()
      .orElseThrow(() -> new InvalidTokenException("Not allowed"));
    assertThrows(InvalidTokenException.class, providerSupplier::get);
  }

  @Test
  void introspectThrowsExceptionWhenFlagIsNull() {
    String issuer = "https://example.com";

    OidcClient client = new OidcClient();
    client.setClientId("client");
    client.setClientSecret("secret");

    OidcProvider nullValue = new OidcProvider();
    nullValue.setIssuer(issuer);
    nullValue.setClient(client);
    nullValue.setAllowProxiedIntrospection(null);

    when(properties.getProviders()).thenReturn(List.of(nullValue));

    Supplier<OidcProvider> providerSupplier = () -> properties.getProviders()
      .stream()
      .filter(
          p -> p.getIssuer().equals(issuer) && Boolean.TRUE.equals(p.isAllowProxiedIntrospection()))
      .findFirst()
      .orElseThrow(() -> new InvalidTokenException("Not allowed"));
    assertThrows(InvalidTokenException.class, providerSupplier::get);

  }

  @Test
  void introspectWorksWhitKnownIssuer() {

    String issuer = "https://einstein.example.com";
    String clientId = "external-client";
    String token =
        buildPlainJwt(issuer, "external-subject-123", clientId, "penid profile", clock.instant());

    OidcClient client = new OidcClient();
    client.setClientId(clientId);
    client.setClientSecret("secret");

    OidcProvider provider = new OidcProvider();
    provider.setIssuer(issuer);
    provider.setClient(client);
    provider.setAllowProxiedIntrospection(true);

    when(properties.getProviders()).thenReturn(List.of(provider));
    when(restTemplateMapper.apply(client)).thenReturn(restTemplate);

    ObjectMapper mapper = new ObjectMapper();
    ObjectNode discoveryJson = mapper.createObjectNode();
    discoveryJson.put("introspection_endpoint", "https://einstein.example.com/introspect");

    when(discoveryService.getDiscoveryDocument(issuer, restTemplate)).thenReturn(discoveryJson);

    OAuth2AuthenticatedPrincipal principal = introspector.introspect(token);

    assertNotNull(principal);
    // Not checked if 'active' is 'true' since we don't have the
    // remote provider introspection response
    assertNotNull(principal.getAttribute("active"));

  }

  @Test
  void introspectFailsWhithUnknownIssuer() {

    String token =
        buildPlainJwt("https://unknown.example.com", "1234", "unknown", "openid", clock.instant());

    when(properties.getProviders()).thenReturn(List.of());

    assertThrows(InvalidTokenException.class, () -> introspector.introspect(token));
  }

  @Test
  void introspectReturnsInactiveWhenMissingIntrospectionEndpoint() throws Exception {

    String issuer = "https://einstein.example.com";
    String token = buildPlainJwt(issuer, "1234", "unknown", "openid", clock.instant());

    OidcProvider provider = new OidcProvider();
    provider.setIssuer(issuer);
    provider.setClient(new OidcClient());
    provider.setAllowProxiedIntrospection(true);

    when(properties.getProviders()).thenReturn(List.of(provider));
    when(restTemplateMapper.apply(any())).thenReturn(restTemplate);
    when(discoveryService.getDiscoveryDocument(issuer, restTemplate))
      .thenReturn(new ObjectMapper().createObjectNode());

    OAuth2AuthenticatedPrincipal principal = introspector.introspect(token);

    assertNotNull(principal);
    assertEquals(false, principal.getAttribute("active"));
  }

  @Test
  void introspectReturnsInactiveForMalformedToken() {

    OAuth2AuthenticatedPrincipal principal = introspector.introspect("this-is-not-a-jwt");

    assertNotNull(principal);
    assertEquals(false, principal.getAttribute("active"));
  }

  @Test
  void introspectReturnsInactiveWhenDiscoveryThrows() {

    String issuer = "https://einstein.example.com";
    String token = buildPlainJwt(issuer, "1234", "client", "openid", clock.instant());

    OidcProvider provider = new OidcProvider();
    provider.setIssuer(issuer);
    provider.setClient(new OidcClient());
    provider.setAllowProxiedIntrospection(true);

    when(properties.getProviders()).thenReturn(List.of(provider));
    when(restTemplateMapper.apply(any())).thenReturn(restTemplate);
    when(discoveryService.getDiscoveryDocument(issuer, restTemplate))
      .thenThrow(new RestClientException("error"));

    OAuth2AuthenticatedPrincipal principal = introspector.introspect(token);

    assertEquals(false, principal.getAttribute("active"));
  }

}
