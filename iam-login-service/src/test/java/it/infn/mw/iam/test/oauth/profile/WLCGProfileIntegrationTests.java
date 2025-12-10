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

import static com.nimbusds.jwt.JWTClaimNames.AUDIENCE;
import static com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME;
import static com.nimbusds.jwt.JWTClaimNames.ISSUED_AT;
import static com.nimbusds.jwt.JWTClaimNames.ISSUER;
import static com.nimbusds.jwt.JWTClaimNames.JWT_ID;
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgJWTProfile.PROFILE_VERSION;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.function.Supplier;

import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@ActiveProfiles({"h2", "wlcg-scopes"})
@TestPropertySource(properties = {
// @formatter:off
  "iam.jwt-profile.default-profile=wlcg",
  "iam.access_token.include_authn_info=true",
  "iam.access_token.include_nbf=true",
  // @formatter:on
})
public class WLCGProfileIntegrationTests extends EndpointsTestUtils {

  private static final String TEST_USER = "test";
  private static final String EXPECTED_USER_NOT_FOUND = "Expected user not found";
  public static final IamAttribute TEST_ATTR = IamAttribute.newInstance(TEST_USER, TEST_USER);

  private static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
  private static final String PASSWORD_GRANT_TYPE = "password";

  private static final String CLIENT_CREDENTIALS_CLIENT_ID = "client-cred";
  private static final String CLIENT_CREDENTIALS_CLIENT_SECRET = "secret";

  private static final String TOKEN_EXCHANGE_GRANT_TYPE =
      TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
  private static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";

  private static final String CLIENT_ID = "password-grant";
  private static final String CLIENT_SECRET = "secret";
  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  private static final String USER_SUBJECT = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";

  private static final String SUBJECT_CLIENT_ID = "token-exchange-subject";
  private static final String SUBJECT_CLIENT_SECRET = "secret";

  private static final String ACTOR_CLIENT_ID = "token-exchange-actor";
  private static final String ACTOR_CLIENT_SECRET = "secret";

  private static final String ALL_AUDIENCES_VALUE = "https://wlcg.cern.ch/jwt/v1/any";

  @Autowired
  private IamAccountRepository repo;

  @Autowired
  private IamProperties properties;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private MockOAuth2Filter oauth2Filter;

  @BeforeEach
  void setup() {
    oauth2Filter.cleanupSecurityContext();
    repo.touchLastLoginTimeForUserWithUsername(USERNAME);
  }

  @AfterEach
  void teardown() {
    oauth2Filter.cleanupSecurityContext();
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  private void setOAuthAdminSecurityContext() {
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    Authentication userAuth = new UsernamePasswordAuthenticationToken("admin", "",
        AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN"));

    String[] authnScopes = new String[] {"openid"};

    OAuth2Authentication authn =
        new OAuth2Authentication(new MockOAuth2Request("password-grant", authnScopes), userAuth);

    authn.setAuthenticated(true);
    authn.setDetails("No details");

    context.setAuthentication(authn);

    oauth2Filter.setSecurityContext(context);
  }

  @Test
  void testWlcgProfile() throws Exception {

    TokenEndpointResponse response = getPasswordTokenResponse("openid profile");
    JWTClaimsSet claims = JWTParser.parse(response.accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim(NOT_BEFORE), notNullValue());
    List<String> scopes = List.of(claims.getStringClaim(IamExtraClaimNames.SCOPE).split(" "));
    assertThat(scopes, hasItems("openid", "profile"));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), nullValue());
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem(ALL_AUDIENCES_VALUE));
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());

    response = getPasswordTokenResponse("openid profile wlcg.groups offline_access");
    claims = JWTParser.parse(response.accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim(NOT_BEFORE), notNullValue());
    scopes = List.of(claims.getStringClaim(IamExtraClaimNames.SCOPE).split(" "));
    assertThat(scopes, hasItems("openid", "profile", "offline_access"));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), notNullValue());
    List<String> groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Production", "/Analysis"));
    assertThat(groups, not(hasItems("/Optional")));
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem(ALL_AUDIENCES_VALUE));
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());

    String refreshToken = response.refreshToken();
    response = getRefreshTokenResponse(refreshToken, "openid profile");
    claims = JWTParser.parse(response.accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim(NOT_BEFORE), notNullValue());
    scopes = List.of(claims.getStringClaim(IamExtraClaimNames.SCOPE).split(" "));
    assertThat(scopes, hasItems("openid", "profile"));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), nullValue());
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem(ALL_AUDIENCES_VALUE));
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());

    response = getRefreshTokenResponse(refreshToken, "openid profile wlcg.groups");
    claims = JWTParser.parse(response.accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim(NOT_BEFORE), notNullValue());
    scopes = List.of(claims.getStringClaim(IamExtraClaimNames.SCOPE).split(" "));
    assertThat(scopes, hasItems("openid", "profile", "wlcg.groups"));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), notNullValue());
    groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Production", "/Analysis"));
    assertThat(groups, not(hasItems("/Optional")));
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem(ALL_AUDIENCES_VALUE));
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());

    response = getRefreshTokenResponse(refreshToken, "openid profile wlcg.groups:/Optional");
    claims = JWTParser.parse(response.accessToken()).getJWTClaimsSet();
    scopes = List.of(claims.getStringClaim(IamExtraClaimNames.SCOPE).split(" "));
    assertThat(scopes, hasItems("openid", "profile", "wlcg.groups:/Optional"));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), notNullValue());
    groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Production", "/Analysis", "/Optional"));
    assertThat(groups.get(0), is("/Optional"));
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem(ALL_AUDIENCES_VALUE));
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());

    response = getRefreshTokenResponse(refreshToken, "openid profile wlcg.groups:/Production");
    claims = JWTParser.parse(response.accessToken()).getJWTClaimsSet();
    scopes = List.of(claims.getStringClaim(IamExtraClaimNames.SCOPE).split(" "));
    assertThat(scopes, hasItems("openid", "profile", "wlcg.groups:/Production"));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), notNullValue());
    groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Production", "/Analysis"));
    assertThat(groups, not(hasItems("/Optional")));
    assertThat(groups.get(0), is("/Production"));
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem(ALL_AUDIENCES_VALUE));
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());

    String subjectToken = response.accessToken();
    response = getExchangeTokenResponse(subjectToken, "openid profile wlcg.groups:/Optional",
        "https://new.audience.example/");
    claims = JWTParser.parse(response.accessToken()).getJWTClaimsSet();
    scopes = List.of(claims.getStringClaim(IamExtraClaimNames.SCOPE).split(" "));
    assertThat(scopes, hasItems("openid", "profile", "wlcg.groups:/Optional"));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), notNullValue());
    groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Production", "/Analysis", "/Optional"));
    assertThat(groups.get(0), is("/Optional"));
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem("https://new.audience.example/"));
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());
  }

  @Test
  void testWlcgProfileIdToken() throws Exception {

    String idTokenString = (String) new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile email wlcg")
      .getTokenResponseObject()
      .getAdditionalInformation()
      .get("id_token");

    JWTClaimsSet claims = JWTParser.parse(idTokenString).getJWTClaimsSet();
    // WLCG required claims
    assertThat(claims.getClaim(SUBJECT), is(TEST_UUID));
    assertThat(claims.getClaim(EXPIRATION_TIME), notNullValue());
    assertThat(claims.getClaim(ISSUER), is(properties.getIssuer()));
    assertThat(claims.getClaim(AUDIENCE), notNullValue());
    assertThat(claims.getAudience(), hasSize(1));
    assertThat(claims.getAudience(), hasItem(CLIENT_ID));
    assertThat(claims.getClaim(ISSUED_AT), notNullValue());
    assertThat(claims.getClaim(NOT_BEFORE), notNullValue());
    assertThat(claims.getClaim(JWT_ID), notNullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.AUTH_TIME), notNullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim(IamExtraClaimNames.GROUPS), nullValue());
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_GROUPS), notNullValue());
    assertThat(claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS),
        hasItems("/Analysis", "/Production"));
    assertThat(claims.getClaim(StandardClaimNames.NAME), is(TEST_NAME));
    assertThat(claims.getClaim(StandardClaimNames.PREFERRED_USERNAME), is(USERNAME));
    assertThat(claims.getClaim(StandardClaimNames.EMAIL), is(TEST_EMAIL));
    assertThat(claims.getClaim(IamExtraClaimNames.ORGANISATION_NAME), notNullValue());
  }

  @Test
  void testWlcgProfileAudience() throws Exception {


    String accessToken = new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .audience("test-audience-1 test-audience-2")
      .getAccessTokenValue();

    JWT token = JWTParser.parse(accessToken);

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_GROUPS), nullValue());
    assertThat(token.getJWTClaimsSet().getAudience(), hasSize(2));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("test-audience-1"));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("test-audience-2"));

    accessToken = new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .getAccessTokenValue();

    token = JWTParser.parse(accessToken);

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_GROUPS), nullValue());
    assertThat(token.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem(ALL_AUDIENCES_VALUE));

  }

  @Test
  void testWlcgProfileResourceIndicator() throws Exception {


    String accessToken = new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .resource("http://example1.org http://example2.org")
      .getAccessTokenValue();

    JWT token = JWTParser.parse(accessToken);

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_GROUPS), nullValue());
    assertThat(token.getJWTClaimsSet().getAudience(), hasSize(2));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("http://example2.org"));

    accessToken = new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .resource("http://example1.org http://example2.org")
      .audience("aud1 aud2")
      .getAccessTokenValue();

    token = JWTParser.parse(accessToken);

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_GROUPS), nullValue());
    assertThat(token.getJWTClaimsSet().getAudience(), hasSize(2));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("http://example1.org"));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("http://example2.org"));

    accessToken = new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .getAccessTokenValue();

    token = JWTParser.parse(accessToken);

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_GROUPS), nullValue());
    assertThat(token.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("https://wlcg.cern.ch/jwt/v1/any"));

  }

  @Test
  void testWlcgProfileGroups() throws Exception {

    TokenEndpointResponse tokens = getPasswordToken("openid profile wlcg.groups");
    JWTClaimsSet claims = JWTParser.parse(tokens.accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim("scope"), is("openid profile wlcg.groups"));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim("nbf"), notNullValue());
    assertThat(claims.getClaim("groups"), nullValue());
    assertThat(claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS),
        hasItems("/Production", "/Analysis"));
  }

  @Test
  void testWlcgProfileGroupRequest() throws Exception {

    TokenEndpointResponse tokens = getPasswordToken("openid profile wlcg.groups:/Analysis");
    JWTClaimsSet claims = JWTParser.parse(tokens.accessToken()).getJWTClaimsSet();

    List<String> scopes = List.of(claims.getStringClaim("scope").split(" "));
    assertThat(scopes, hasItems("openid", "profile", "wlcg.groups:/Analysis"));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim("nbf"), notNullValue());
    assertThat(claims.getClaim("groups"), nullValue());
    List<String> groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Production", "/Analysis"));
    assertThat(groups, not(hasItems("/Optional")));
    assertThat(groups.get(0), is("/Analysis"));
    assertThat(groups.get(1), is("/Production"));

    tokens = getPasswordToken("openid profile wlcg.groups:/Production");
    claims = JWTParser.parse(tokens.accessToken()).getJWTClaimsSet();

    scopes = List.of(claims.getStringClaim("scope").split(" "));
    assertThat(scopes, hasItems("openid", "profile", "wlcg.groups:/Production"));
    assertThat(claims.getClaim(WlcgExtraClaimNames.WLCG_VER), is(PROFILE_VERSION));
    assertThat(claims.getClaim("nbf"), notNullValue());
    assertThat(claims.getClaim("groups"), nullValue());
    groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Production", "/Analysis"));
    assertThat(groups, not(hasItems("/Optional")));
    assertThat(groups.get(0), is("/Production"));
    assertThat(groups.get(1), is("/Analysis"));
  }

  @Test
  void testWlcgProfileOptionalGroupRequest() throws Exception {

    TokenEndpointResponse tokens = getPasswordToken("openid profile wlcg.groups:/Optional");
    JWTClaimsSet claims = JWTParser.parse(tokens.accessToken()).getJWTClaimsSet();

    List<String> scopes = List.of(claims.getStringClaim("scope").split(" "));
    assertThat(scopes, hasItems("openid", "profile", "wlcg.groups:/Optional"));
    assertThat(scopes.size(), is(3));
    List<String> groups = claims.getStringListClaim(WlcgExtraClaimNames.WLCG_GROUPS);
    assertThat(groups, hasItems("/Optional", "/Production", "/Analysis"));
    assertThat(groups.get(0), is("/Optional"));
    assertThat(groups.size(), is(3));
  }

  @Test
  void testWlcgProfileClientCredentials() throws Exception {

    String response = mvc
      .perform(post("/token")
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "storage.read:/a-path storage.write:/another-path"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("storage.read:/a-path")))
      .andExpect(jsonPath("$.scope", containsString("storage.write:/another-path")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    DefaultOAuth2AccessToken tokenResponseObject =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    JWT accessToken = JWTParser.parse(tokenResponseObject.getValue());

    String scope = accessToken.getJWTClaimsSet().getStringClaim("scope");
    assertThat(scope, containsString("storage.read:/a-path"));
    assertThat(scope, containsString("storage.write:/another-path"));

    assertThat(accessToken.getJWTClaimsSet().getStringClaim("client_id"),
        is(CLIENT_CREDENTIALS_CLIENT_ID));

    assertThat(accessToken.getJWTClaimsSet().getSubject(), is(CLIENT_CREDENTIALS_CLIENT_ID));

  }

  @Test
  void testWlcgProfileGroupRequestClientCredentials() throws Exception {

    String response = mvc
      .perform(post("/token")
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "storage.read:/a-path wlcg.groups"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("storage.read:/a-path")))
      .andExpect(jsonPath("$.scope", containsString(WlcgExtraClaimNames.WLCG_GROUPS)))
      .andReturn()
      .getResponse()
      .getContentAsString();


    DefaultOAuth2AccessToken tokenResponseObject =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    JWT accessToken = JWTParser.parse(tokenResponseObject.getValue());

    assertThat(accessToken.getJWTClaimsSet().getClaim(WlcgExtraClaimNames.WLCG_GROUPS),
        nullValue());

  }


  @Test
  void testWlcgProfileServiceIdentityTokenExchange() throws Exception {

    String subjectToken = new AccessTokenGetter().grantType(CLIENT_CREDENTIALS_GRANT_TYPE)
      .clientId(SUBJECT_CLIENT_ID)
      .clientSecret(SUBJECT_CLIENT_SECRET)
      .scope("storage.read:/ storage.write:/subpath")
      .audience(ACTOR_CLIENT_ID)
      .getAccessTokenValue();

    String tokenResponse = mvc
      .perform(post("/token").with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", subjectToken)
        .param("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
        .param("scope", "storage.read:/subpath storage.write:/subpath/test offline_access")
        .param("audience", "se1.example se2.example"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope",
          allOf(containsString("storage.read:/subpath "), containsString("offline_access"),
              containsString("storage.write:/subpath/test"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    DefaultOAuth2AccessToken tokenResponseObject =
        mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

    JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
    assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(SUBJECT_CLIENT_ID));

    assertThat(exchangedToken.getJWTClaimsSet().getJSONObjectClaim("act").get("sub"),
        is(ACTOR_CLIENT_ID));

    String atScopes = exchangedToken.getJWTClaimsSet().getStringClaim("scope");

    assertThat(atScopes, containsString("storage.read:/subpath"));

    assertThat(atScopes, containsString("storage.write:/subpath/test"));

    assertThat(atScopes, containsString("offline_access"));

    List<String> audiences = exchangedToken.getJWTClaimsSet().getStringListClaim("aud");

    assertThat(audiences, notNullValue());
    assertThat(audiences, hasItems("se1.example", "se2.example"));

    tokenResponse = mvc
      .perform(post("/token").with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
        .param("grant_type", REFRESH_TOKEN_GRANT_TYPE)
        .param("refresh_token", tokenResponseObject.getRefreshToken().getValue()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope",
          allOf(containsString("storage.read:/subpath "), containsString("offline_access"),
              containsString("storage.write:/subpath/test"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    tokenResponseObject = mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

    JWT refreshedToken = JWTParser.parse(tokenResponseObject.getValue());
    assertThat(refreshedToken.getJWTClaimsSet().getSubject(), is(SUBJECT_CLIENT_ID));

    String rtScopes = refreshedToken.getJWTClaimsSet().getStringClaim("scope");

    assertThat(rtScopes, containsString("storage.read:/subpath"));

    assertThat(rtScopes, containsString("storage.write:/subpath/test"));

    assertThat(rtScopes, containsString("offline_access"));

    List<String> rtAudiences = exchangedToken.getJWTClaimsSet().getStringListClaim("aud");

    assertThat(rtAudiences, notNullValue());
    assertThat(rtAudiences, hasItems("se1.example", "se2.example"));

    setOAuthAdminSecurityContext();

  }


  @Test
  void testWlcgProfileUserIdentityTokenExchangeNoScopeParameter() throws Exception {
    String subjectToken = new AccessTokenGetter().grantType(PASSWORD_GRANT_TYPE)
      .clientId(SUBJECT_CLIENT_ID)
      .clientSecret(SUBJECT_CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .audience(ACTOR_CLIENT_ID)
      .getAccessTokenValue();

    mvc
      .perform(post("/token").with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", subjectToken)
        .param("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_request"))
      .andExpect(jsonPath("$.error_description", containsString("scope parameter is required")));
  }

  @Test
  void testWlcgProfileUserIdentityTokenExchange() throws Exception {

    String subjectToken = new AccessTokenGetter().grantType(PASSWORD_GRANT_TYPE)
      .clientId(SUBJECT_CLIENT_ID)
      .clientSecret(SUBJECT_CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("storage.read:/ storage.write:/subpath openid")
      .audience(ACTOR_CLIENT_ID)
      .getAccessTokenValue();

    // Exchange the token to client 'token-exchange-actor', reduce a bit the scopes
    // but request a refresh token
    String tokenResponse =
        mvc
          .perform(post("/token").with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
            .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
            .param("subject_token", subjectToken)
            .param("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
            .param("scope",
                "storage.read:/subpath storage.write:/subpath/test openid offline_access")
            .param("audience", "se1.example se2.example"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.access_token").exists())
          .andExpect(jsonPath("$.refresh_token").exists())
          .andExpect(jsonPath("$.scope",
              allOf(containsString("storage.read:/subpath "), containsString("offline_access"),
                  containsString("storage.write:/subpath/test"), containsString("openid"),
                  containsString("offline_access"))))
          .andReturn()
          .getResponse()
          .getContentAsString();

    DefaultOAuth2AccessToken tokenResponseObject =
        mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

    JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
    assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(USER_SUBJECT));

    assertThat(exchangedToken.getJWTClaimsSet().getJSONObjectClaim("act").get("sub"),
        is(ACTOR_CLIENT_ID));

    // Check that token can be introspected properly
    mvc
      .perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", tokenResponseObject.getValue()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    // Check that the token can be further exchange by the same actor client
    // without the offline_access scope
    tokenResponse = mvc
      .perform(post("/token").with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", tokenResponseObject.getValue())
        .param("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
        .param("scope", "storage.read:/subpath storage.write:/subpath/test openid")
        .param("audience", "se4.example"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").doesNotExist())
      .andExpect(jsonPath("$.scope",
          allOf(containsString("storage.read:/subpath "),
              containsString("storage.write:/subpath/test"), containsString("openid"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    DefaultOAuth2AccessToken tokenResponseObject2 =
        mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

    JWT exchangedToken2 = JWTParser.parse(tokenResponseObject2.getValue());
    assertThat(exchangedToken2.getJWTClaimsSet().getSubject(), is(USER_SUBJECT));

    assertThat(exchangedToken2.getJWTClaimsSet().getJSONObjectClaim("act").get("sub"),
        is(ACTOR_CLIENT_ID));


    JSONObject nestedActClaimValue = (JSONObject) JSONObject
      .wrap(exchangedToken2.getJWTClaimsSet().getJSONObjectClaim("act").get("act"));
    assertThat(nestedActClaimValue.getString("sub"), is(ACTOR_CLIENT_ID));

    // Check that token can be introspected properly
    mvc
      .perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", tokenResponseObject2.getValue()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

  }

  @Test
  void testAudiencePreservedAcrossRefresh() throws Exception {
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile offline_access")
        .param("audience", "test-audience"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("audience", "test-audience"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);
    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), hasItem("test-audience"));
  }

  @Test
  void testAudienceRequestRefreshTokenFlow() throws Exception {
    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JWTClaimsSet claims =
        JWTParser.parse(mapper.readTree(tokenResponseJson).get("access_token").asText())
          .getJWTClaimsSet();

    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), hasItem("https://wlcg.cern.ch/jwt/v1/any"));

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("audience", "test-audience"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    claims = JWTParser.parse(mapper.readTree(tokenResponseJson).get("access_token").asText())
      .getJWTClaimsSet();

    assertNotNull(claims.getAudience());
    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), hasItem("test-audience"));

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    claims = JWTParser.parse(mapper.readTree(tokenResponseJson).get("access_token").asText())
      .getJWTClaimsSet();

    assertThat(claims.getAudience().size(), equalTo(1));
    assertThat(claims.getAudience(), hasItem("https://wlcg.cern.ch/jwt/v1/any"));
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
    scopes = {"openid"})
  void testUserInfoEndpointRetursMinimalInformation() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.email").doesNotExist())
      .andExpect(jsonPath("$.preferred_username").doesNotExist())
      .andExpect(jsonPath("$.given_name").doesNotExist())
      .andExpect(jsonPath("$.family_name").doesNotExist())
      .andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(jsonPath("$.updated_at").doesNotExist());
    // @formatter:on
  }

  @Test
  void testUserInfoEndpointReturnsMinimailInformationAcrossRefresh() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile offline_access email"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshToken = mapper.readTree(tokenResponseJson).get("refresh_token").asText();

    tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "refresh_token")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("refresh_token", refreshToken)
        .param("scope", "openid"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String at = mapper.readTree(tokenResponseJson).get("access_token").asText();

    SecurityContext context = SecurityContextHolder.createEmptyContext();
    Authentication userAuth = new UsernamePasswordAuthenticationToken("test", "",
        AuthorityUtils.createAuthorityList("ROLE_USER"));

    String[] authnScopes = new String[] {"openid"};

    OAuth2Authentication authn =
        new OAuth2Authentication(new MockOAuth2Request("password-grant", authnScopes), userAuth);

    authn.setAuthenticated(true);

    OAuth2AuthenticationDetails details = mock(OAuth2AuthenticationDetails.class);
    when(details.getTokenValue()).thenReturn(at);
    authn.setDetails(details);
    context.setAuthentication(authn);

    oauth2Filter.setSecurityContext(context);

    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.*", hasSize(2)))
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.scope").exists());
  }

  @Test
  void attributesAreNotIncludedInAccessTokenWhenNotRequested() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    accountService.setAttribute(testAccount, TEST_ATTR);

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JWTClaimsSet claims =
        JWTParser.parse(mapper.readTree(tokenResponseJson).get("access_token").asText())
          .getJWTClaimsSet();

    assertThat(claims.getJSONObjectClaim("attr"), nullValue());
  }

  @Test
  void attributesAreIncludedInAccessTokenWhenRequested() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    accountService.setAttribute(testAccount, TEST_ATTR);

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile attr"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JWTClaimsSet claims =
        JWTParser.parse(mapper.readTree(tokenResponseJson).get("access_token").asText())
          .getJWTClaimsSet();

    assertThat(claims.getJSONObjectClaim("attr"), notNullValue());
    assertThat(claims.getJSONObjectClaim("attr").get("test"), is("test"));
  }

  @Test
  void additionalClaimsAreIncludedInAccessTokenWhenRequested() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile email"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JWTClaimsSet claims =
        JWTParser.parse(mapper.readTree(tokenResponseJson).get("access_token").asText())
          .getJWTClaimsSet();

    assertThat(claims.getClaim("email"), notNullValue());
    assertThat(claims.getClaim("email"), is("test@iam.test"));
    assertThat(claims.getClaim("name"), notNullValue());
    assertThat(claims.getClaim("name"), is("Test User"));
    assertThat(claims.getClaim("preferred_username"), notNullValue());
    assertThat(claims.getClaim("preferred_username"), is("test"));
  }

  @Test
  void additionalClaimsAreNotIncludedInAccessTokenWhenRNotequested() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", CLIENT_ID)
        .param("client_secret", CLIENT_SECRET)
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid address"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JWTClaimsSet claims =
        JWTParser.parse(mapper.readTree(tokenResponseJson).get("access_token").asText())
          .getJWTClaimsSet();

    assertThat(claims.getClaim("email"), nullValue());
    assertThat(claims.getClaim("name"), nullValue());
    assertThat(claims.getClaim("preferred_username"), nullValue());
  }

}
