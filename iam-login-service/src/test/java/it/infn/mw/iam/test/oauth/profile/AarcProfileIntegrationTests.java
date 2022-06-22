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

import static it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo.EDUPERSON_ENTITLEMENT_CLAIM;
import static it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo.EDUPERSON_SCOPED_AFFILIATION_CLAIM;
import static it.infn.mw.iam.core.userinfo.IamScopeClaimTranslationService.EDUPERSON_SCOPED_AFFILIATION_SCOPE;
import static java.lang.String.join;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
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
    "iam.organisation.name=org",
    // @formatter:on
})
public class AarcProfileIntegrationTests extends EndpointsTestUtils {

  private static final String CLIENT_ID = "password-grant";
  private static final String CLIENT_SECRET = "secret";
  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";

  private static final String URN_GROUP_ANALYSIS = "urn:example:iam:group:Analysis#example.org";
  private static final String URN_GROUP_PRODUCTION = "urn:example:iam:group:Production#example.org";

  protected static final Set<String> BASE_SCOPES = Sets.newHashSet("openid", "profile");
  protected static final Set<String> EDUPERSON_AFFILIATION_SCOPE =
      Sets.newHashSet("openid", "profile", "email", "eduperson_scoped_affiliation");
  protected static final Set<String> EDUPERSON_ENTITLEMENT_SCOPE =
      Sets.newHashSet("openid", "profile", "eduperson_entitlement");
  protected static final Set<String> EDUPERSON_SCOPES = Sets.newHashSet("openid", "profile",
      "eduperson_scoped_affiliation", "eduperson_scoped_affiliation");


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

  @Test
  public void testEdupersonEntitlementScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "eduperson_entitlement");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_SCOPED_AFFILIATION_SCOPE), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("email"), nullValue());

    List<String> groups = Lists
      .newArrayList(token.getJWTClaimsSet().getStringArrayClaim(EDUPERSON_ENTITLEMENT_CLAIM));
    assertThat(groups, hasSize(2));
    assertThat(groups, hasItem(URN_GROUP_ANALYSIS));
    assertThat(groups, hasItem(URN_GROUP_PRODUCTION));
  }

  @Test
  public void testEdupersonScopedAffiliationScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "eduperson_scoped_affiliation");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_ENTITLEMENT_CLAIM), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("email"), nullValue());

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_SCOPED_AFFILIATION_SCOPE),
        equalTo("org"));
  }

  @Test
  public void testEdupersonScopedAffiliationAndEntitlementScopes() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "eduperson_scoped_affiliation",
        "eduperson_entitlement");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    assertThat(token.getJWTClaimsSet().getClaim("groups"), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim("email"), nullValue());

    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_SCOPED_AFFILIATION_SCOPE),
        equalTo("org"));

    List<String> groups = Lists
      .newArrayList(token.getJWTClaimsSet().getStringArrayClaim(EDUPERSON_ENTITLEMENT_CLAIM));
    assertThat(groups, hasSize(2));
    assertThat(groups, hasItem(URN_GROUP_ANALYSIS));
    assertThat(groups, hasItem(URN_GROUP_PRODUCTION));
  }

  @Test
  public void testAarcProfileIntrospect() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "eduperson_entitlement");
    JWT token = JWTParser.parse(getAccessTokenForUser(scopes));

    // @formatter:off
    mvc.perform(post("/introspect")
        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
        .param("token", token.getParsedString()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("org")))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")));
    // @formatter:on

  }

  @Test
  @WithMockOAuthUser(clientId = CLIENT_ID, user = USERNAME, authorities = {"ROLE_USER"},
      scopes = {"openid profile eduperson_scoped_affiliation eduperson_entitlement"})
  public void testAarcProfileUserinfo() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("org")))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = CLIENT_ID, user = USERNAME, authorities = {"ROLE_USER"},
      scopes = {"openid profile email eduperson_scoped_affiliation eduperson_entitlement"})
  public void testAarcProfileUserinfoWithEmail() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_SCOPED_AFFILIATION_CLAIM, equalTo("org")))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT_CLAIM, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")))
      .andExpect(jsonPath("$.email_verified", equalTo(true)));
    // @formatter:on
  }

}
