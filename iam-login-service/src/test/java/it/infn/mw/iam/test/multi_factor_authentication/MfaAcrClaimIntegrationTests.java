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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class MfaAcrClaimIntegrationTests extends TestTokensUtils {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TESTUSER_USERNAME = "test-with-mfa";
  public static final String[] SCOPES = {"openid", "profile"};

  @After
  public void teardown() {
    SecurityContextHolder.clearContext();
    clearAllTokens();
  }

  @Test
  public void testAcrClaimInTokensAndIntrospectionWhenMfaEnabled() throws Exception {

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    OAuth2AccessTokenEntity accessToken = buildAccessToken(client, TESTUSER_USERNAME, SCOPES);
    assertEquals("https://referds.org/profile/MFA",
        accessToken.getJwt().getJWTClaimsSet().getClaim("acr"));

    mvc
      .perform(post("/introspect").with(httpBasic(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .param("token", accessToken.getValue()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.acr").exists())
      .andExpect(jsonPath("$.acr", containsString("https://referds.org/profile/MFA")));
  }

}
