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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.NoSuchElementException;

import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
public class TokenExchangeDisableUpscopingTests extends EndpointsTestUtils {

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    private static final String TOKEN_ENDPOINT = "/token";

    private static final String ACTOR_CLIENT_ID = "token-exchange-actor";
    private static final String ACTOR_CLIENT_SECRET = "secret";

    private String accessToken;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private IamProperties properties;

    @Autowired
    private IamClientRepository clientRepository;

    @Before
    public void setup() throws Exception {
        accessToken = new AccessTokenGetter().grantType("client_credentials")
            .clientId("client-cred")
            .clientSecret("secret")
            .scope("read-tasks")
            .getAccessTokenValue();

        ClientDetailsEntity client = clientRepository.findByClientId("client-cred")
            .orElseThrow(NoSuchElementException::new);
        client.setUpScopingAllowed(false);
        clientRepository.save(client);
    }


    @After
    public void cleanUp() {
        ClientDetailsEntity client = clientRepository.findByClientId("client-cred")
            .orElseThrow(NoSuchElementException::new);
        client.setUpScopingAllowed(true);
        clientRepository.save(client);
    }

    @Test
    public void testTokenExchangeForClientCredentialsDisableUpscopingSuccess() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope", allOf(containsString("read-tasks"))))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is("client-cred"));
    }

    @Test
    public void testTokenExchangeForClientCredentialsDisableUpscopingFail() throws Exception {

        mvc.perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessToken)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", "profile"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description")
                .value("scope not allowed by subject token configuration: profile"));
    }

    @Test
    @DirtiesContext
    public void testTokenExchangeForClientCredentialsDisableUpscopingDisableTokenScopes()
            throws Exception {
        properties.getAccessToken().setIncludeScope(false);

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope", allOf(containsString("read-tasks"))))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is("client-cred"));

        properties.getAccessToken().setIncludeAuthnInfo(true);
    }

    @Test
    @DirtiesContext
    public void testTokenExchangeForClientCredentialsDisableUpscopingTokenWithoutScopes()
            throws Exception {
        properties.getAccessToken().setIncludeScope(false);

        MockHttpServletRequestBuilder req = post("/token").param("grant_type", "client_credentials")
            .param("client_id", "client-cred")
            .param("client_secret", "secret");

        String response = mvc.perform(req)
            .andExpect(status().is(200))
            .andReturn()
            .getResponse()
            .getContentAsString();

        String accessTokenNoScopes =
                mapper.readValue(response, DefaultOAuth2AccessToken.class).getValue();

        properties.getAccessToken().setIncludeScope(true);

        mvc.perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessTokenNoScopes)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", "profile"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_request"))
            .andExpect(jsonPath("$.error_description")
                .value("cannot verify requested scopes with subject token"));

    }


    @Test
    public void testTokenExchangeForClientCredentialsDisableUpscopingIncludingOfflineScope()
            throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks offline_access"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope", allOf(containsString("read-tasks offline_access"))))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is("client-cred"));
    }
}
