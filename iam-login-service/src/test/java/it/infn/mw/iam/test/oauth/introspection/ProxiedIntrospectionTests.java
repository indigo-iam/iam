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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClientException;
import org.springframework.http.MediaType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@ActiveProfiles({ "h2", "oidc-test" })
public class ProxiedIntrospectionTests extends EndpointsTestUtils {

    /*
     * @Autowired
     * OidcProviderProperties properties;
     * 
     * @Test
     * public void checkConfiguration() {
     * assertTrue(properties.getProviders().size() == 2);
     * JWT jwt = new PlainJWT();
     * }
     */

    @Autowired
    OidcProviderProperties properties;

    @MockBean
    private OpaqueTokenIntrospector opaqueTokenIntrospector;

    @Test
    public void testProxiedIntrospectionWithEinsteinProvider() throws Exception {

        String externalIssuer = "https://einstein.example.com";
        String externalToken = buildJwtWithIssuer(externalIssuer);

        /*
         * Map of attributes an external provider should return
         * during introspection
         */
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("active", true);
        attrs.put("iss", externalIssuer);
        attrs.put("client_id", "client-einstein");
        attrs.put("scope", "openid profile email");

        OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(attrs, List.of());

        when(opaqueTokenIntrospector.introspect(externalToken)).thenReturn(principal);

        // Executes a POST request to the introspection endpoint
        mvc.perform(post(INTROSPECTION_ENDPOINT)
                .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                
                .param("token", externalToken)
                .param("token_type_hint", TokenTypeHint.ACCESS_TOKEN.name()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active", equalTo(true)))
            .andExpect(jsonPath("$.iss", equalTo(externalIssuer)))
            .andExpect(jsonPath("$.client_id", equalTo("client-einstein")))
            .andExpect(jsonPath("$.scope", equalTo("openid profile email")));
    }

    @Test
    public void testProxiedIntrospectionWithOppenheimerProvider() throws Exception {

        String externalIssuer = "https://oppenheimer.example.com";
        String externalToken = buildJwtWithIssuer(externalIssuer);

        /*
         * Map of attributes an external provider should return
         * during introspection
         */
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("active", true);
        attrs.put("iss", externalIssuer);
        attrs.put("client_id", "client-oppenheimer");
        attrs.put("scope", "openid profile email");

        OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(attrs, List.of());

        when(opaqueTokenIntrospector.introspect(externalToken)).thenReturn(principal);

        // Executes a POST request to the introspection endpoint
        mvc.perform(post(INTROSPECTION_ENDPOINT)
                .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("token", externalToken)
                .param("token_type_hint", TokenTypeHint.ACCESS_TOKEN.name()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active", equalTo(true)))
            .andExpect(jsonPath("$.iss", equalTo(externalIssuer)))
            .andExpect(jsonPath("$.client_id", equalTo("client-oppenheimer")))
            .andExpect(jsonPath("$.scope", equalTo("openid profile email")));
    }

     @Test
    public void testProxiedIntrospectionWithRestClientException() throws Exception {

        String externalIssuer = "https://oppenheimer.example.com";
        String externalToken = buildJwtWithIssuer(externalIssuer);

        when(opaqueTokenIntrospector.introspect(externalToken)).thenThrow(new RestClientException("Error"));

        // Executes a POST request to the introspection endpoint
        mvc.perform(post(INTROSPECTION_ENDPOINT)
                .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("token", externalToken)
                .param("token_type_hint", TokenTypeHint.ACCESS_TOKEN.name()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active", equalTo(false)));
    }

    // Builds a JWT with a specified issuer
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
