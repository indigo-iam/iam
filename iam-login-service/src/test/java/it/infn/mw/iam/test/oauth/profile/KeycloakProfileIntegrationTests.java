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
package it.infn.mw.iam.test.oauth.profile;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.jwt-profile.default-profile=kc",})
class KeycloakProfileIntegrationTests extends EndpointsTestUtils {

  private static final String CLIENT_ID = "password-grant";
  private static final String CLIENT_SECRET = "secret";
  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  protected static final String KC_GROUP_CLAIM = "roles";

  private String getAccessTokenForUser(String scopes) throws Exception {

    return new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope(scopes)
      .getAccessTokenValue();
  }

  private String getAccessTokenWithAudience(String scopes, String audience) throws Exception {

    return new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope(scopes)
      .audience(audience)
      .getAccessTokenValue();
  }

  @Test
  void testKeycloakProfileAccessToken() throws Exception {
    JWT token = JWTParser.parse(getAccessTokenForUser("openid profile"));

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("roles"), notNullValue());
    List<String> roles =
        Lists.newArrayList(token.getJWTClaimsSet().getStringArrayClaim(KC_GROUP_CLAIM));
    assertThat(roles, hasSize(3));
    assertThat(roles, hasItems("Analysis", "Optional", "Production"));
  }

  @Test
  void testKeycloakProfileAccessTokenForClientWithNoRoles() throws Exception {
    String accessTokenString = (String) new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username("admin")
      .password("password")
      .scope("openid profile")
      .getAccessTokenValue();

    JWT jwt = JWTParser.parse(accessTokenString);
    assertThat(jwt.getJWTClaimsSet().getClaim("roles"), nullValue());
  }

  @Test
  void testKeycloakProfileAccessTokenWithClientCredentials() throws Exception {
    String accessTokenString = (String) new AccessTokenGetter().grantType("client_credentials")
      .clientId("client-cred")
      .clientSecret("secret")
      .scope("openid profile")
      .getAccessTokenValue();

    assertThat(!accessTokenString.contains("roles"), is(true));

  }

  @Test
  void testKeycloackProfileIntrospect() throws Exception {

    JWT token = JWTParser.parse(getAccessTokenForUser("openid profile"));

    mvc
      .perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(
          jsonPath("$." + KC_GROUP_CLAIM, containsInAnyOrder("Analysis", "Production", "Optional")))
      .andExpect(jsonPath("$." + KC_GROUP_CLAIM, hasSize(equalTo(3))))
      .andExpect(jsonPath("$.iss", equalTo("http://localhost:8080/")))
      .andExpect(jsonPath("$.scope", containsString("openid")))
      .andExpect(jsonPath("$.scope", containsString("profile")));

  }

  @Test
  void testKeycloackProfileIntrospectWithAudience() throws Exception {

    JWT token = JWTParser.parse(getAccessTokenWithAudience("openid profile", "myAudience"));

    mvc
      .perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.aud", equalTo("myAudience")));

  }

  @Test
  void testKeycloackProfileForUserNotInGroups() throws Exception {

    String accessTokenString = (String) new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username("admin")
      .password("password")
      .scope("openid profile")
      .getAccessTokenValue();

    mvc
      .perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessTokenString))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.roles").doesNotExist());

  }
}
