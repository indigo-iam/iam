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
package it.infn.mw.iam.test.client.last_used;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.time.LocalDate;
import java.util.Collections;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;


@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamNoMvcTest
public class ClientLastUsedTests {

    public static final String POST_CLIENT = "post-client";
    public static final String TOKEN_LOOKUP_CLIENT = "token-lookup-client";
    public static final String TEST_347_USER = "test_347";
    public static final String[] SCOPES = {"offline_access"};

    @Autowired
    IamProperties iamProperties;

    @Autowired
    private ClientDetailsEntityService clientDetailsService;

    @Autowired
    private DefaultOAuth2ProviderTokenService tokenService;

    private OAuth2Authentication buildAuth(String username, String clientId, String... scopes) {
        Authentication userAuth = new UsernamePasswordAuthenticationToken(username, "");
        MockOAuth2Request req = new MockOAuth2Request(clientId, scopes);
        return new OAuth2Authentication(req, userAuth);
    }

    @Test
    public void testClientLastUsedCreationOnTokenCreation() {
        // Initially, the last used is null
        ClientDetailsEntity client = clientDetailsService.loadClientByClientId(TOKEN_LOOKUP_CLIENT);
        assertNull(client.getClientLastUsed());

        // When the last used date is not tracked, it is not updated and remains null
        iamProperties.getClient().setTrackLastUsed(false);
        OAuth2Authentication auth = buildAuth(TEST_347_USER, TOKEN_LOOKUP_CLIENT);
        tokenService.createAccessToken(auth);
        assertNull(client.getClientLastUsed());

        // When the last used date is tracked, it is created with the current date
        iamProperties.getClient().setTrackLastUsed(true);
        tokenService.createAccessToken(auth);
        assertNotNull(client.getClientLastUsed());
        LocalDate lastUsed = client.getClientLastUsed().getLastUsed();
        LocalDate today = LocalDate.now();
        assertEquals(today, lastUsed);
    }

    @Test
    public void testLastUsedUpdateOnTokenCreation() {
        iamProperties.getClient().setTrackLastUsed(true);

        // Initially, the last used date is set to the default value
        ClientDetailsEntity client = clientDetailsService.loadClientByClientId(POST_CLIENT);
        assertNotNull(client.getClientLastUsed());
        LocalDate lastUsed = client.getClientLastUsed().getLastUsed();
        LocalDate defaultDate = LocalDate.of(1994, 3, 19);
        assertEquals(defaultDate, lastUsed);

        // After creating a token, the last used date is updated
        OAuth2Authentication auth = buildAuth(TEST_347_USER, POST_CLIENT, SCOPES);
        tokenService.createAccessToken(auth);
        assertNotNull(client.getClientLastUsed());
        lastUsed = client.getClientLastUsed().getLastUsed();
        LocalDate today = LocalDate.now();
        assertEquals(today, lastUsed);
    }

    @Test
    public void testClientLastUsedCreationOnTokenRefresh() {
        iamProperties.getClient().setTrackLastUsed(false);

        ClientDetailsEntity client = clientDetailsService.loadClientByClientId(TOKEN_LOOKUP_CLIENT);
        assertThat(client.isAllowRefresh());

        // Initially, the last used date is null
        OAuth2Authentication auth = buildAuth(TEST_347_USER, TOKEN_LOOKUP_CLIENT, SCOPES);
        OAuth2AccessTokenEntity accessToken = tokenService.createAccessToken(auth);
        assertNull(client.getClientLastUsed());

        // After refreshing the access token, the last used date is created with the current date
        iamProperties.getClient().setTrackLastUsed(true);
        OAuth2RefreshTokenEntity refreshToken = accessToken.getRefreshToken();
        TokenRequest tokenRequest =
                new TokenRequest(emptyMap(), TOKEN_LOOKUP_CLIENT, Collections.emptySet(), "");
        tokenService.refreshAccessToken(refreshToken.getValue(), tokenRequest);
        assertNotNull(client.getClientLastUsed());
        LocalDate lastUsed = client.getClientLastUsed().getLastUsed();
        LocalDate today = LocalDate.now();
        assertEquals(today, lastUsed);
    }

    @Test
    public void testClientLastUsedUpdateOnTokenRefresh() {
        iamProperties.getClient().setTrackLastUsed(false);

        // Get a client with a default last used date and able to generate refresh tokens
        ClientDetailsEntity client = clientDetailsService.loadClientByClientId(POST_CLIENT);
        client.setGrantTypes(Set.of("refresh_token"));
        assertThat(client.isAllowRefresh());

        // Initially, the last used date is set to the default value
        assertNotNull(client.getClientLastUsed());
        LocalDate lastUsed = client.getClientLastUsed().getLastUsed();
        LocalDate defaultDate = LocalDate.of(1994, 3, 19);
        assertEquals(defaultDate, lastUsed);

        // After creating an access token, the last used date is not updated
        OAuth2Authentication auth = buildAuth(TEST_347_USER, POST_CLIENT, SCOPES);
        OAuth2AccessTokenEntity accessToken = tokenService.createAccessToken(auth);
        assertNotNull(client.getClientLastUsed());
        lastUsed = client.getClientLastUsed().getLastUsed();
        assertEquals(defaultDate, lastUsed);

        // After refreshing the access token, the last used date is updated
        iamProperties.getClient().setTrackLastUsed(true);
        OAuth2RefreshTokenEntity refreshToken = accessToken.getRefreshToken();
        TokenRequest tokenRequest =
                new TokenRequest(emptyMap(), POST_CLIENT, Collections.emptySet(), "");
        tokenService.refreshAccessToken(refreshToken.getValue(), tokenRequest);
        assertNotNull(client.getClientLastUsed());
        lastUsed = client.getClientLastUsed().getLastUsed();
        LocalDate today = LocalDate.now();
        assertEquals(today, lastUsed);
    }

}
