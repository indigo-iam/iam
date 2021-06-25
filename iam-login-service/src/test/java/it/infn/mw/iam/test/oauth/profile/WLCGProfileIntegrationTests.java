/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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


import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;
import net.minidev.json.JSONObject;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@Transactional
@TestPropertySource(properties = {
// @formatter:off
    "iam.jwt-profile.default-profile=wlcg",
    "scope.matchers[0].name=storage.read",
    "scope.matchers[0].type=path",
    "scope.matchers[0].prefix=storage.read",
    "scope.matchers[0].path=/",
    "scope.matchers[1].name=storage.write",
    "scope.matchers[1].type=path",
    "scope.matchers[1].prefix=storage.write",
    "scope.matchers[1].path=/",
    "scope.matchers[2].name=wlcg.groups",
    "scope.matchers[2].type=regexp",
    "scope.matchers[2].regexp=^wlcg\\.groups(?::((?:\\/[a-zA-Z0-9][a-zA-Z0-9_.-]*)+))?$",
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

  private static final String ANOTHER_TOKEN_EXCHANGE_CLIENT_ID = "token-lookup-client";
  private static final String ANOTHER_TOKEN_EXCHANGE_CLIENT_SECRET = "secret";

  private static final String ALL_AUDIENCES_VALUE = "https://wlcg.cern.ch/jwt/v1/any";

  @Autowired
  private WebApplicationContext context;

  @Autowired
  IamProperties iamProperties;

  @Autowired
  IamAccountRepository repo;

  @Autowired
  IamAccountService accountService;

  @Autowired
  MockOAuth2Filter oauth2Filter;

  @Before
  public void setup() {
    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @After
  public void teardown() {
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

  private String getAccessTokenForUser(String scopes) throws Exception {

    return new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope(scopes)
      .getAccessTokenValue();
  }

  @Test
  @WithAnonymousUser
  public void testWlcgProfile() throws Exception {
    JWT token = JWTParser.parse(getAccessTokenForUser("openid profile"));

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.ver"), is("1.0"));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem(ALL_AUDIENCES_VALUE));
  }

  @Test
  @WithAnonymousUser
  public void testWlcgProfileIdToken() throws Exception {

    String idTokenString = (String) new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile wlcg.groups")
      .getTokenResponseObject()
      .getAdditionalInformation()
      .get("id_token");

    JWT idToken = JWTParser.parse(idTokenString);
    assertThat(idToken.getJWTClaimsSet().getClaim("wlcg.ver"), is("1.0"));
    assertThat(idToken.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(idToken.getJWTClaimsSet().getClaim("wlcg.groups"), notNullValue());
    assertThat(idToken.getJWTClaimsSet().getStringListClaim("wlcg.groups"),
        hasItems("/Analysis", "/Production"));
    assertThat(idToken.getJWTClaimsSet().getClaim("name"), is("Test User"));
    assertThat(idToken.getJWTClaimsSet().getClaim("preferred_username"), is("test"));
    assertThat(idToken.getJWTClaimsSet().getClaim("organisation_name"), is("indigo-dc"));
    assertThat(idToken.getJWTClaimsSet().getClaim("auth_time"), notNullValue());
    assertThat(idToken.getJWTClaimsSet().getClaim("jti"), notNullValue());
    assertThat(idToken.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(idToken.getJWTClaimsSet().getAudience(), hasItem("password-grant"));
  }

  @Test
  @WithAnonymousUser
  public void testWlcgProfileAudience() throws Exception {


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
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.ver"), is("1.0"));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.groups"), nullValue());
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
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.ver"), is("1.0"));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getAudience(), hasSize(1));
    assertThat(token.getJWTClaimsSet().getAudience(), hasItem("https://wlcg.cern.ch/jwt/v1/any"));

  }

  @Test
  @WithAnonymousUser
  public void testWlcgProfileGroups() throws Exception {
    JWT token = JWTParser.parse(getAccessTokenForUser("openid profile wlcg.groups"));

    assertThat(token.getJWTClaimsSet().getClaim("scope"), is("openid profile wlcg.groups"));
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.ver"), is("1.0"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getStringListClaim("wlcg.groups"),
        hasItems("/Production", "/Analysis"));
  }

  @Test
  @WithAnonymousUser
  public void testWlcgProfileGroupRequest() throws Exception {
    JWT token = JWTParser.parse(getAccessTokenForUser("openid profile wlcg.groups:/Analysis"));

    assertThat(token.getJWTClaimsSet().getClaim("scope"),
        is("openid profile wlcg.groups:/Analysis"));
    assertThat(token.getJWTClaimsSet().getClaim("wlcg.ver"), is("1.0"));
    assertThat(token.getJWTClaimsSet().getClaim("nbf"), notNullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getStringListClaim("wlcg.groups"),
        hasItems("/Production", "/Analysis"));
  }

  @Test
  public void testWlcgProfileClientCredentials() throws Exception {

    mvc
      .perform(post("/token")
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "storage.read:/a-path storage.write:/another-path"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("storage.read:/a-path")))
      .andExpect(jsonPath("$.scope", containsString("storage.write:/another-path")));
  }

  @Test
  public void testWlcgProfileGroupRequestClientCredentials() throws Exception {

    String response = mvc
      .perform(post("/token")
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "storage.read:/a-path wlcg.groups"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("storage.read:/a-path")))
      .andExpect(jsonPath("$.scope", containsString("wlcg.groups")))
      .andReturn()
      .getResponse()
      .getContentAsString();


    DefaultOAuth2AccessToken tokenResponseObject =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    JWT accessToken = JWTParser.parse(tokenResponseObject.getValue());

    assertThat(accessToken.getJWTClaimsSet().getClaim("wlcg.groups"), nullValue());

  }


  @Test
  public void testWlcgProfileServiceIdentityTokenExchange() throws Exception {

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

    assertThat(exchangedToken.getJWTClaimsSet().getJSONObjectClaim("act").getAsString("sub"),
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

    mvc.perform(get("/iam/api/refresh-tokens")).andExpect(status().isOk());

  }

  @Test
  public void testWlcgProfileUserIdentityTokenExchange() throws Exception {

    String subjectToken = new AccessTokenGetter().grantType(PASSWORD_GRANT_TYPE)
      .clientId(SUBJECT_CLIENT_ID)
      .clientSecret(SUBJECT_CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("storage.read:/ storage.write:/subpath openid")
      .audience(ACTOR_CLIENT_ID)
      .getAccessTokenValue();

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

    assertThat(exchangedToken.getJWTClaimsSet().getJSONObjectClaim("act").getAsString("sub"),
        is(ACTOR_CLIENT_ID));

    // Check that token can be introspected properly
    mvc
      .perform(post("/introspect").with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", tokenResponseObject.getValue()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

    mvc
      .perform(post("/token").with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", tokenResponseObject.getValue())
        .param("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
        .param("scope", "storage.read:/subpath storage.write:/subpath/test openid offline_access")
        .param("audience", "se4.example"))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error").value("access_denied"))
      .andExpect(jsonPath("$.error_description",
          containsString("the actor and the subject are the same client")));


    tokenResponse = mvc
      .perform(post("/token")
        .with(httpBasic(ANOTHER_TOKEN_EXCHANGE_CLIENT_ID, ANOTHER_TOKEN_EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", tokenResponseObject.getValue())
        .param("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
        .param("scope", "openid offline_access")
        .param("audience", "se5.example"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists())
      .andExpect(jsonPath("$.refresh_token").exists())
      .andExpect(jsonPath("$.scope",
          allOf(containsString("offline_access"), containsString("openid"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    DefaultOAuth2AccessToken tokenResponseObject2 =
        mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

    JWT exchangedToken2 = JWTParser.parse(tokenResponseObject2.getValue());
    assertThat(exchangedToken2.getJWTClaimsSet().getSubject(), is(USER_SUBJECT));

    assertThat(exchangedToken2.getJWTClaimsSet().getJSONObjectClaim("act").getAsString("sub"),
        is(ANOTHER_TOKEN_EXCHANGE_CLIENT_ID));


    JSONObject nestedActClaimValue =
        (JSONObject) exchangedToken2.getJWTClaimsSet().getJSONObjectClaim("act").get("act");
    assertThat(nestedActClaimValue.getAsString("sub"), is(ACTOR_CLIENT_ID));

    // Check that token can be introspected properly
    mvc
      .perform(post("/introspect").with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", tokenResponseObject2.getValue()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)));

  }

  @Test
  public void testAudiencePreservedAcrossRefresh() throws Exception {
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
  public void testAudienceRequestRefreshTokenFlow() throws Exception {
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
  public void testUserInfoEndpointRetursMinimalInformation() throws Exception {

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
  public void testUserInfoEndpointReturnsMinimailInformationAcrossRefresh() throws Exception {

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
      .andExpect(jsonPath("$.*", hasSize(1)))
      .andExpect(jsonPath("$.sub").exists());
  }

  @Test
  public void attributesAreNotIncludedInAccessTokenWhenNotRequested() throws Exception {
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
  public void attributesAreIncludedInAccessTokenWhenNotRequested() throws Exception {
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
    assertThat(claims.getJSONObjectClaim("attr").getAsString("test"), is("test"));
  }


}
