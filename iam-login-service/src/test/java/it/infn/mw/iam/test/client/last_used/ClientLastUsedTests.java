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

import static org.junit.Assert.assertEquals;

import java.time.LocalDate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;


@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamNoMvcTest
public class ClientLastUsedTests {

    public static final String TEST_CLIEND_ID = "post-client";
    public static final String TEST_347_USER = "admin";
    public static final String[] SCOPES = {"openid", "profile", "offline_access"};

    @Autowired
    IamProperties iamProperties;

    @Autowired
    private ClientDetailsEntityService clientDetailsService;

    @Autowired
    private DefaultOAuth2ProviderTokenService tokenService;

    @Test
    public void testLastUsedUpdate() {

        iamProperties.getClient().setTrackLastUsed(true);

        ClientDetailsEntity client = clientDetailsService.loadClientByClientId(TEST_CLIEND_ID);

        LocalDate lastUsed = client.getClientLastUsed().getLastUsed();
        LocalDate defaultDate = LocalDate.of(1994, 3, 19);
        assertEquals(defaultDate, lastUsed);

        Authentication userAuth =
                new UsernamePasswordAuthenticationToken(TEST_347_USER, "password");
        MockOAuth2Request req = new MockOAuth2Request(client.getClientId(), SCOPES);
        OAuth2Authentication auth = new OAuth2Authentication(req, userAuth);
        OAuth2AccessTokenEntity token = tokenService.createAccessToken(auth);

        lastUsed = token.getClient().getClientLastUsed().getLastUsed();
        LocalDate today = LocalDate.now();
        assertEquals(today, lastUsed);
    }

}
