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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
public class MfaAcrClaimIntegrationTests extends TestTokensUtils {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TESTUSER_USERNAME = "test-with-mfa";

  @AfterEach
  void teardown() {
    SecurityContextHolder.clearContext();
    clearAllTokens();
  }

  @Test
  void testAcrClaimInTokensAndIntrospectionWhenMfaEnabled() throws Exception {

    SavedUserAuthentication savedAuth = new SavedUserAuthentication();
    savedAuth.setName(TESTUSER_USERNAME);
    savedAuth.setAuthenticated(true);
    savedAuth.setAuthorities(List.of(new SimpleGrantedAuthority("ROLE_USER")));
    savedAuth.getAdditionalInfo().put("acr", "https://refeds.org/profile/mfa");

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    OAuth2Request req = new OAuth2Request(Map.of("grant_type", "authorization_code"),
        client.getClientId(), null, true, Set.of("openid"), null, null, null, null);

    OAuth2Authentication auth = new OAuth2Authentication(req, savedAuth);

    OAuth2AccessTokenEntity token = tokenService.createAccessToken(auth);

    JWTClaimsSet atClaims = JWTParser.parse(token.getValue()).getJWTClaimsSet();
    assertThat(atClaims.getClaim("acr")).isEqualTo("https://refeds.org/profile/mfa");

    String idToken = String.valueOf(token.getAdditionalInformation().get("id_token"));
    JWTClaimsSet idTokenClaims = JWTParser.parse(idToken).getJWTClaimsSet();
    assertThat(idTokenClaims.getClaim("acr")).isEqualTo("https://refeds.org/profile/mfa");

    mvc
      .perform(post("/introspect").with(httpBasic(TEST_CLIENT_ID, TEST_CLIENT_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", token.getValue())
        .param("token_type_hint", TokenTypeHint.ACCESS_TOKEN.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.acr").exists())
      .andExpect(jsonPath("$.acr", containsString("https://refeds.org/profile/mfa")));
  }
}
