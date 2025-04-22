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


import static it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo.EDUPERSON_ASSURANCE_CLAIM;
import static it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo.EDUPERSON_ENTITLEMENT_CLAIM;
import static it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo.ENTITLEMENTS_CLAIM;
import static it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo.EDUPERSON_SCOPED_AFFILIATION_CLAIM;
import static java.lang.String.join;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.hamcrest.Matchers.empty;

import java.util.List;
import java.util.Set;


import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {
// @formatter:off
    "iam.host=example.org",
    "iam.jwt-profile.default-profile=aarc",
    // @formatter:on
})
public class AarcProfileIntegrationTests extends EndpointsTestUtils {

  private static final String CLIENT_ID = "password-grant";
  private static final String CLIENT_SECRET = "secret";
  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  private static final String GRANT_TYPE = "password";

  private static final String URN_GROUP_ANALYSIS = "urn:geant:iam.example:group:Analysis";
  private static final String URN_GROUP_PRODUCTION = "urn:geant:iam.example:group:Production";

  private static final String ASSURANCE = "https://refeds.org/assurance";
  private static final String ASSURANCE_VALUE = "https://refeds.org/assurance/IAP/low";

  protected static final Set<String> BASE_SCOPES = Sets.newHashSet("openid", "profile");
  protected static final Set<String> EDUPERSON_AFFILIATION_SCOPE =
      Sets.newHashSet("openid", "profile", "email", "eduperson_scoped_affiliation");
  protected static final Set<String> ENTITLEMENTS_SCOPE =
      Sets.newHashSet("openid", "profile", "entitlements");
  protected static final Set<String> EDUPERSON_ASSURANCE_SCOPE =
      Sets.newHashSet("openid", "profile", "eduperson_assurance");
  protected static final Set<String> EDUPERSON_SCOPES = Sets.newHashSet("openid", "profile",
      "eduperson_scoped_affiliation", "entitlements", "eduperson_assurance");


  @Autowired
  private MockOAuth2Filter oauth2Filter;

  @Before
  public void setup() {
    oauth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    oauth2Filter.cleanupSecurityContext();
  }

  private String getAccessTokenForUser(Set<String> scopes) throws Exception {

    return getAccessTokenForUser(join(" ", scopes));
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

  @SuppressWarnings("deprecation")
  private String getIdToken(String scopes) throws Exception {

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("grant_type", GRANT_TYPE)
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", scopes))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    DefaultOAuth2AccessToken tokenResponse =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    return tokenResponse.getAdditionalInformation().get("id_token").toString();
  }

  @Test
  public void testEdupersonEntitlementScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "entitlements");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_SCOPED_AFFILIATION_CLAIM), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_ENTITLEMENT_CLAIM), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("email"), nullValue());

    List<String> groups =
        Lists.newArrayList(token.getJWTClaimsSet().getStringArrayClaim(ENTITLEMENTS_CLAIM));
    assertThat(groups, hasSize(2));
    assertThat(groups, hasItem(URN_GROUP_ANALYSIS));
    assertThat(groups, hasItem(URN_GROUP_PRODUCTION));

    Set<String> scopes2 =
        Sets.newHashSet("openid", "profile", "entitlements", "eduperson_entitlement");
    JWT token2 = JWTParser.parse(getAccessTokenForUser(scopes2));
    assertThat(token2.getJWTClaimsSet().getClaim(ENTITLEMENTS_CLAIM), notNullValue());
    assertThat(token2.getJWTClaimsSet().getClaim(EDUPERSON_ENTITLEMENT_CLAIM), notNullValue());

    Set<String> scopes3 = Sets.newHashSet("openid", "profile", "eduperson_entitlement");
    JWT token3 = JWTParser.parse(getAccessTokenForUser(scopes3));
    assertThat(token3.getJWTClaimsSet().getClaim(ENTITLEMENTS_CLAIM), notNullValue());
    assertThat(token3.getJWTClaimsSet().getClaim(EDUPERSON_ENTITLEMENT_CLAIM), notNullValue());
  }

  @Test
  public void testEdupersonScopedAffiliationScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "eduperson_scoped_affiliation");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertThat(token.getJWTClaimsSet().getClaim(ENTITLEMENTS_CLAIM), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("email"), nullValue());

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_SCOPED_AFFILIATION_CLAIM),
        equalTo("member@iam.example"));
  }

  @Test
  public void testEdupersonAssuranceScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "eduperson_assurance");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_SCOPED_AFFILIATION_CLAIM), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(ENTITLEMENTS_CLAIM), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("email"), nullValue());

    List<String> assurance =
        Lists.newArrayList(token.getJWTClaimsSet().getStringArrayClaim(EDUPERSON_ASSURANCE_CLAIM));
    assertThat(assurance, hasSize(2));
    assertThat(assurance, hasItem(ASSURANCE));
    assertThat(assurance, hasItem(ASSURANCE_VALUE));
  }

  @Test
  public void testEdupersonScopedAffiliationAndEntitlementScopes() throws Exception {

    Set<String> scopes =
        Sets.newHashSet("openid", "profile", "eduperson_scoped_affiliation", "entitlements");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("email"), nullValue());

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_SCOPED_AFFILIATION_CLAIM),
        equalTo("member@iam.example"));

    List<String> groups =
        Lists.newArrayList(token.getJWTClaimsSet().getStringArrayClaim(ENTITLEMENTS_CLAIM));
    assertThat(groups, hasSize(2));
    assertThat(groups, hasItem(URN_GROUP_ANALYSIS));
    assertThat(groups, hasItem(URN_GROUP_PRODUCTION));
  }

  @Test
  public void testAarcProfileIntrospect() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "entitlements", "eduperson_assurance");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    // @formatter:off
    mvc.perform(post("/introspect")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")));
    // @formatter:on

  }

  @Test
  public void testAarcProfileIntrospectWithOldScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "eduperson_entitlement", "eduperson_assurance");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    // @formatter:off
    mvc.perform(post("/introspect")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")));
    // @formatter:on

  }

  @Test
  public void testAarcProfileIntrospectWithoutScopes() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    // @formatter:off
    mvc.perform(post("/introspect")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM).doesNotExist())
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM).doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM).doesNotExist())
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")));
    // @formatter:on

  }

  @Test
  @WithMockOAuthUser(clientId = CLIENT_ID, user = USERNAME, authorities = {"ROLE_USER"},
      scopes = {"openid profile eduperson_scoped_affiliation entitlements eduperson_assurance"})
  public void testAarcProfileUserinfo() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = CLIENT_ID, user = USERNAME, authorities = {"ROLE_USER"}, scopes = {
      "openid profile email eduperson_scoped_affiliation entitlements eduperson_assurance"})
  public void testAarcProfileUserinfoWithEmail() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")))
      .andExpect(jsonPath("$.email_verified", equalTo(true)));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = CLIENT_ID, user = USERNAME, authorities = {"ROLE_USER"}, scopes = {
      "openid profile email eduperson_scoped_affiliation entitlements eduperson_assurance"})
  public void testAarcProfileUserinfoWithVoperson_id() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$.voperson_id").isNotEmpty())
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")))
      .andExpect(jsonPath("$.email_verified", equalTo(true)));
    // @formatter:on
  }

  @Test
  public void testAarcProfileIntrospectWithoutScopesWithVoperson_id() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertNotNull(token.getJWTClaimsSet().getClaim("voperson_id"));

    // @formatter:off
    mvc.perform(post("/introspect")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.voperson_id").isNotEmpty())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM).doesNotExist())
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM).doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM).doesNotExist())
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")));
    // @formatter:on

  }

  @Test
  public void testAarcProfileIntrospectWithOldScopeWithVoperson_id() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "eduperson_entitlement", "eduperson_assurance");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertNotNull(token.getJWTClaimsSet().getClaim("voperson_id"));

    // @formatter:off
    mvc.perform(post("/introspect")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.voperson_id").isNotEmpty())
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")));
    // @formatter:on

  }

  @Test
  public void testAarcProfileIntrospectWithVoperson_id() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "entitlements", "eduperson_assurance");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertNotNull(token.getJWTClaimsSet().getClaim("voperson_id"));

    // @formatter:off
    mvc.perform(post("/introspect")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.voperson_id").isNotEmpty())
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE_CLAIM, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")));
    // @formatter:on

  }

  @Test
  public void testAarcProfileIdTokenWithVoperson_id() throws Exception {

    JWT token = JWTParser.parse(getIdToken("openid email"));
    System.out.println(token.getJWTClaimsSet());
    assertNotNull(token.getJWTClaimsSet().getClaim("sub"));
    assertNotNull(token.getJWTClaimsSet().getClaim("voperson_id"));
    assertNotEquals(token.getJWTClaimsSet().getClaim("voperson_id"), empty());
  }

  @Test
  public void testAarcProfileAccessTokenWithVoperson_id() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "eduperson_entitlement", "eduperson_assurance");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertNotNull(token.getJWTClaimsSet().getClaim("voperson_id"));
    assertNotEquals(token.getJWTClaimsSet().getClaim("voperson_id"), empty());


  }


}
