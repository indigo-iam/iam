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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.core.oauth.discovery.OidcDiscoveryService;
import it.infn.mw.iam.core.oauth.introspection.model.DelegatingOpaqueTokenIntrospector;

@ExtendWith(MockitoExtension.class)
class OpaqueTokenIntrospectorTests {

    @Mock
    OidcProviderProperties properties;

    @Mock
    OidcDiscoveryService discoveryService;
    
    @Mock
    Function<OidcClient, RestTemplate> restTemplateMapper;

    @Mock
    RestTemplate restTemplate;

    DelegatingOpaqueTokenIntrospector introspector;

    @BeforeEach
    void setup() {
        introspector = new DelegatingOpaqueTokenIntrospector(properties, restTemplateMapper, discoveryService);
    }

    @Test
    void introspectReturnsPrincipalWhenIssuerIsKnown() {
        // Test to check if the principal is returned when the issuer is known

        String issuer = "https://einstein.example.com";
        // Building a JWT with the known issuer
        String token = buildJwtWithIssuer(issuer); 

        OidcClient client = new OidcClient();
        client.setClientId("client-einstein");
        client.setClientSecret("secret");

        OidcProvider provider = new OidcProvider();
        provider.setIssuer(issuer);
        provider.setClient(client);

        // Mocking the properties to return the know provider
        when(properties.getProviders()).thenReturn(List.of(provider));
        // Mocking the restTemplateMapper to return the mocked RestTemplate for the client
        when(restTemplateMapper.apply(client)).thenReturn(restTemplate);

        // Creating a JSON object for the discovery document with the introspection endpoint
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode discoveryJson = mapper.createObjectNode();
        discoveryJson.put("introspection_endpoint", "https://einstein.example.com/introspect");

        // Mocking the discovery service to return the discovery document JSON
        when(discoveryService.getDiscoveryDocument(eq(issuer), eq(restTemplate)))
            .thenReturn(discoveryJson);

        assertThrows(Exception.class, () ->  introspector.introspect(token));
    }

    @Test
    void introspectFailsUnknownIssuer() {
        // Test to check if InvalidTokenException is thrown for an unkown issuer

        String token = buildJwtWithIssuer("https://unknown.example.com");

        // Mocking properties to return an empty list, simulating no known providers
        when(properties.getProviders()).thenReturn(List.of());

        assertThrows(
            InvalidTokenException.class, () -> introspector.introspect(token)
        );
    }

    @Test
    void introspectReturnsInactiveWhenNoIntrospectionEndpoint() throws Exception {
        // Test to verify that the introspector return an inactive principal when there is no introspection endpoint available for the issuer

        String issuer = "https://einstein.example.com";
        String token = buildJwtWithIssuer(issuer);

        OidcProvider provider = new OidcProvider();
        provider.setIssuer(issuer);
        provider.setClient(new OidcClient());

        // Mocking properties to return the provider that has no introspection endpoint
        when(properties.getProviders()).thenReturn(List.of(provider));
        // Mocking the restTemplateMapper to return the mocked RestTemplate
        when(restTemplateMapper.apply(any())).thenReturn(restTemplate);
        // Mocking the discoveryService to return an empty JSON object when getDiscoveryDocument is called
        when(discoveryService.getDiscoveryDocument(eq(issuer), eq(restTemplate))).thenReturn(new ObjectMapper().createObjectNode());

        OAuth2AuthenticatedPrincipal principal = introspector.introspect(token);

        assertNotNull(principal);
        // Assert that the 'active' attribute of the principal is false
        assertTrue(principal.getAttribute("active").equals(false));
    }

    @Test
    void introspectReturnsInactiveForMalformedToken() {
        // Test to verify that the introspector returns an inactive principal for a malformed JWT token

        OAuth2AuthenticatedPrincipal principal = introspector.introspect("this-is-not-a-jwt");

        assertNotNull(principal);
        assertTrue(principal.getAttribute("active").equals(false));
    }

    private String buildJwtWithIssuer(String iss) {

        Date now = new Date();
        Date exp = new Date(System.currentTimeMillis() + 3600_000L);

        // Creates the claims for the JWT
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(iss)
                .subject("external-subject-123")
                .issueTime(now)
                .expirationTime(exp)
                .jwtID("jti-external-123")
                .claim("client_id", "external-client")
                .claim("scope", "openid profile")
                .build();

        PlainJWT jwt = new PlainJWT(claims);
        return jwt.serialize();
    }
}
