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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
class TokenExchangeIncludeScopeEnableUpScopingTests extends EndpointsTestUtils {

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    private static final String TOKEN_ENDPOINT = "/token";

    private static final String ACTOR_CLIENT_ID = "token-exchange-actor";
    private static final String ACTOR_CLIENT_SECRET = "secret";

    private String accessToken;

    @Autowired
    private ObjectMapper mapper;

    @BeforeAll
    void setup() throws Exception {
        accessToken = new AccessTokenGetter().grantType("client_credentials")
            .clientId("client-cred")
            .clientSecret("secret")
            .scope("read-tasks")
            .getAccessTokenValue();
    }

    // Upscoping Enabled, Access token with scopes, Iam settings with scopes, no upscoping
    @Test
    void testTokenExchangeForClientCredentialsSuccess() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope", containsString("read-tasks")))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is("client-cred"));

        // Scopes should be present in access token
        assertEquals("read-tasks", exchangedToken.getJWTClaimsSet().getClaim("scope"));
    }

    // Upscoping Enabled, Access token with scopes, Iam settings with scopes, using upscoping in
    // exchange
    @Test
    void testTokenExchangeForClientCredentialsUpscopingSuccess() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "storage.read:/"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope", containsString("storage.read:/")))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is("client-cred"));

        // Scopes should be present in access token
        assertEquals("storage.read:/", exchangedToken.getJWTClaimsSet().getClaim("scope"));
    }

    // Upscoping Enabled, Access token without scopes, Iam settings without scopes, Using upscoping
    // in the exchange for offline access
    @Test
    void testTokenExchangeForClientCredentialsUpscopingOfflineScope() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks offline_access"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope",
                    allOf(containsString("offline_access"), containsString("read-tasks"))))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is("client-cred"));

        // Scopes should be present in access token
        assertThat((String) exchangedToken.getJWTClaimsSet().getClaim("scope"),
                containsString("offline_access"));
        assertThat((String) exchangedToken.getJWTClaimsSet().getClaim("scope"),
                containsString("read-tasks"));
    }
}
