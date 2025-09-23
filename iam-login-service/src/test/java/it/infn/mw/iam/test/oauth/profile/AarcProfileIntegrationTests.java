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
import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes.EDUPERSON_ASSURANCE;
import static it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes.EDUPERSON_ENTITLEMENT;
import static it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes.ENTITLEMENTS;
import static it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes.VOPERSON_ID;
import static it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes.VOPERSON_SCOPED_AFFILIATION;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.oauth2.core.oidc.OidcScopes.OPENID;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.oauth.profile.aarc.AarcExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes;
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
    "iam.access-token.include-authn-info=true"
    // @formatter:on
})
@SuppressWarnings("deprecation")
public class AarcProfileIntegrationTests extends EndpointsTestUtils {

  private static final String URN_GROUP_ANALYSIS = "urn:geant:iam.example:group:Analysis";
  private static final String URN_GROUP_PRODUCTION = "urn:geant:iam.example:group:Production";

  private static final String ASSURANCE = "https://refeds.org/assurance";
  private static final String ASSURANCE_VALUE = "https://refeds.org/assurance/IAP/low";

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

  private String getIdToken(String scopes) throws Exception {

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET))
        .param("grant_type", "password")
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
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

    Set<String> scopes = Sets.newHashSet("openid", "entitlements");
    JWTClaimsSet claims = SignedJWT.parse(getPasswordToken(scopes).accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim(SUBJECT), equalTo(TEST_UUID));
    assertThat(claims.getClaim(VOPERSON_SCOPED_AFFILIATION), nullValue());
    assertThat(claims.getClaim(EDUPERSON_ENTITLEMENT), nullValue());

    List<String> groups = Lists.newArrayList(claims.getStringArrayClaim(ENTITLEMENTS));
    assertThat(groups, hasSize(2));
    assertThat(groups, hasItem(URN_GROUP_ANALYSIS));
    assertThat(groups, hasItem(URN_GROUP_PRODUCTION));

    Set<String> scopes2 = Sets.newHashSet(OPENID, ENTITLEMENTS, EDUPERSON_ENTITLEMENT);
    JWTClaimsSet claims2 =
        SignedJWT.parse(getPasswordToken(scopes2).accessToken()).getJWTClaimsSet();

    assertThat(claims2.getClaim(ENTITLEMENTS), notNullValue());
    assertThat(claims2.getClaim(EDUPERSON_ENTITLEMENT), notNullValue());

    Set<String> scopes3 = Sets.newHashSet(OPENID, EDUPERSON_ENTITLEMENT);
    JWTClaimsSet claims3 =
        SignedJWT.parse(getPasswordToken(scopes3).accessToken()).getJWTClaimsSet();

    assertThat(claims3.getClaim(ENTITLEMENTS), notNullValue());
    assertThat(claims3.getClaim(EDUPERSON_ENTITLEMENT), notNullValue());
  }

  @Test
  public void testEdupersonScopedAffiliationScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "eduperson_scoped_affiliation");
    SignedJWT token = SignedJWT.parse(getPasswordToken(scopes).accessToken());

    assertThat(token.getJWTClaimsSet().getClaim("sub"), equalTo(TEST_UUID));
    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_ASSURANCE), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(ENTITLEMENTS), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(VOPERSON_ID), nullValue());

    assertThat(token.getJWTClaimsSet().getClaim(VOPERSON_SCOPED_AFFILIATION),
        equalTo("member@iam.example"));
  }

  @Test
  public void testEdupersonAssuranceScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "eduperson_assurance");
    SignedJWT token = SignedJWT.parse(getPasswordToken(scopes).accessToken());

    assertThat(token.getJWTClaimsSet().getClaim("sub"), equalTo(TEST_UUID));
    assertThat(token.getJWTClaimsSet().getClaim(VOPERSON_SCOPED_AFFILIATION), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(ENTITLEMENTS), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(VOPERSON_ID), nullValue());

    List<String> assurance =
        Lists.newArrayList(token.getJWTClaimsSet().getStringArrayClaim(EDUPERSON_ASSURANCE));

    assertThat(assurance, hasSize(2));
    assertThat(assurance, hasItem(ASSURANCE));
    assertThat(assurance, hasItem(ASSURANCE_VALUE));
  }

  @Test
  public void testVoPersonIdScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "voperson_id");
    SignedJWT token = SignedJWT.parse(getPasswordToken(scopes).accessToken());

    assertThat(token.getJWTClaimsSet().getClaim("sub"), equalTo(TEST_UUID));
    assertThat(token.getJWTClaimsSet().getClaim(VOPERSON_ID),
        equalTo(TEST_UUID + "@" + ORGANISATION_NAME));
    assertThat(token.getJWTClaimsSet().getClaim(EDUPERSON_ASSURANCE), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(VOPERSON_SCOPED_AFFILIATION), nullValue());
    assertThat(token.getJWTClaimsSet().getClaim(ENTITLEMENTS), nullValue());
  }

  @Test
  public void testAarcProfileIntrospect() throws Exception {

    Set<String> scopes = Sets.newHashSet(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL,
        AarcOidcScopes.VOPERSON_SCOPED_AFFILIATION, AarcOidcScopes.ENTITLEMENTS,
        AarcOidcScopes.EDUPERSON_ASSURANCE, AarcOidcScopes.VOPERSON_ID);
    String accessToken = getPasswordToken(scopes).accessToken();

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$." + VOPERSON_ID, equalTo(TEST_UUID + "@" + ORGANISATION_NAME)));
    // @formatter:on

  }

  @Test
  public void testAarcProfileIntrospectWithOldEdupersonEntitlementsScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "eduperson_entitlement", "eduperson_assurance");
    String accessToken = getPasswordToken(scopes).accessToken();

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ENTITLEMENT, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + ENTITLEMENTS, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)));
    // @formatter:on

  }

  @Test
  public void testAarcProfileIntrospectWithoutScopes() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email");
    String accessToken = getPasswordToken(scopes).accessToken();

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION).doesNotExist())
      .andExpect(jsonPath("$." + ENTITLEMENTS).doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE).doesNotExist())
      .andExpect(jsonPath("$." + VOPERSON_ID).doesNotExist());
    // @formatter:on

  }

  @Test
  public void testAarcProfileIntrospectWithNoUser() throws Exception {

    String accessToken = getClientCredentialsToken("openid profile").accessToken();

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION).doesNotExist())
      .andExpect(jsonPath("$." + ENTITLEMENTS).doesNotExist())
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE).doesNotExist())
      .andExpect(jsonPath("$." + VOPERSON_ID).doesNotExist());
    // @formatter:on

  }

  @Test
  @WithMockOAuthUser(clientId = PASSWORD_CLIENT_ID, user = TEST_USERNAME,
      authorities = {"ROLE_USER"}, scopes = {"openid aarc"})
  public void testAarcProfileUserinfo() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$." + VOPERSON_ID, equalTo(TEST_UUID + "@" + ORGANISATION_NAME)));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = PASSWORD_CLIENT_ID, user = TEST_USERNAME,
      authorities = {"ROLE_USER"}, scopes = {
          "openid profile email eduperson_scoped_affiliation entitlements eduperson_assurance"})
  public void testAarcProfileUserinfoWithEmail() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")))
      .andExpect(jsonPath("$.email_verified", equalTo(true)));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = PASSWORD_CLIENT_ID, user = TEST_USERNAME,
      authorities = {"ROLE_USER"}, scopes = {
          "openid profile email eduperson_scoped_affiliation entitlements eduperson_assurance voperson_id"})
  public void testAarcProfileUserinfoWithAllScopes() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name").doesNotExist())
      .andExpect(jsonPath("$.groups").doesNotExist())
      .andExpect(jsonPath("$." + VOPERSON_ID).isNotEmpty())
      .andExpect(jsonPath("$." + VOPERSON_ID, equalTo(TEST_UUID + "@" + ORGANISATION_NAME)))
      .andExpect(jsonPath("$." + VOPERSON_SCOPED_AFFILIATION, equalTo("member@iam.example")))
      .andExpect(jsonPath("$." + ENTITLEMENTS, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + ENTITLEMENTS, containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, hasSize(equalTo(2))))
      .andExpect(jsonPath("$." + EDUPERSON_ASSURANCE, containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.name", equalTo("Test User")))
      .andExpect(jsonPath("$.given_name", equalTo("Test")))
      .andExpect(jsonPath("$.family_name", equalTo("User")))
      .andExpect(jsonPath("$.email", equalTo("test@iam.test")))
      .andExpect(jsonPath("$.email_verified", equalTo(true)));
    // @formatter:on
  }

  @Test
  public void testAarcProfileIdTokenWithNoScopes() throws Exception {

    JWTClaimsSet claims = JWTParser.parse(getIdToken("openid")).getJWTClaimsSet();
    assertNotNull(claims.getClaim(SUBJECT));
    assertNull(claims.getClaim(VOPERSON_ID));
    assertNull(claims.getClaim(ENTITLEMENTS));
    assertNull(claims.getClaim(VOPERSON_SCOPED_AFFILIATION));
    assertNull(claims.getClaim(EDUPERSON_ASSURANCE));
  }

  @Test
  public void testAarcProfileIdTokenWithAarcScope() throws Exception {

    JWTClaimsSet claims = JWTParser.parse(getIdToken("openid aarc")).getJWTClaimsSet();
    assertNotNull(claims.getClaim(SUBJECT));
    assertNotNull(claims.getClaim(AarcExtraClaimNames.VOPERSON_ID));
    assertNotNull(claims.getClaim(AarcExtraClaimNames.ENTITLEMENTS));
    assertNotNull(claims.getClaim(AarcExtraClaimNames.VOPERSON_SCOPED_AFFILIATION));
    assertNotNull(claims.getClaim(AarcExtraClaimNames.EDUPERSON_ASSURANCE));
    // no external authentication, expected null
    assertNull(claims.getClaim(AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION));
    // null legacy claims
    assertNull(claims.getClaim(AarcExtraClaimNames.EDUPERSON_ENTITLEMENT));
    assertNull(claims.getClaim(AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testAarcProfileIdTokenWithAllSeparatedAarcScopes() throws Exception {

    Set<String> scopes = Set.of("openid", "eduperson_scoped_affiliation", "entitlements",
        "eduperson_assurance", "voperson_id");
    JWTClaimsSet claims = JWTParser.parse(getPasswordToken(scopes).idToken()).getJWTClaimsSet();

    assertNotNull(claims.getClaim("sub"));
    assertThat(claims.getClaim("sub"), is(TEST_UUID));
    assertNotNull(claims.getClaim("aud"));
    assertThat(claims.getClaim("aud"), is(List.of(PASSWORD_CLIENT_ID)));
    assertNotNull(claims.getClaim(VOPERSON_ID));
    assertThat(claims.getClaim(VOPERSON_ID), is(TEST_UUID + "@" + ORGANISATION_NAME));
    assertNotNull(claims.getClaim(ENTITLEMENTS));
    assertThat(claims.getClaim(ENTITLEMENTS), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim(ENTITLEMENTS),
        containsInAnyOrder(URN_GROUP_PRODUCTION, URN_GROUP_ANALYSIS));
    assertNotNull(claims.getClaim(VOPERSON_SCOPED_AFFILIATION));
    assertThat(claims.getClaim(VOPERSON_SCOPED_AFFILIATION), is("member@iam.example"));
    assertNotNull(claims.getClaim(EDUPERSON_ASSURANCE));
    assertThat(claims.getClaim(EDUPERSON_ASSURANCE), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim(EDUPERSON_ASSURANCE),
        containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testAarcProfileIdTokenWithLegacyAarcScopes() throws Exception {

    Set<String> scopes = Set.of(OidcScopes.OPENID, AarcOidcScopes.EDUPERSON_ENTITLEMENT,
        AarcOidcScopes.EDUPERSON_SCOPED_AFFILIATION);
    JWTClaimsSet claims = JWTParser.parse(getPasswordToken(scopes).idToken()).getJWTClaimsSet();

    assertThat(claims.getClaim(SUBJECT), is(TEST_UUID));
    assertThat(claims.getClaim(AUDIENCE), is(List.of(PASSWORD_CLIENT_ID)));
    // legacy entitlements
    assertThat(claims.getClaim(AarcExtraClaimNames.EDUPERSON_ENTITLEMENT),
        instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim(AarcExtraClaimNames.EDUPERSON_ENTITLEMENT),
        containsInAnyOrder(URN_GROUP_PRODUCTION, URN_GROUP_ANALYSIS));
    // entitlements
    assertThat(claims.getClaim(ENTITLEMENTS), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim(ENTITLEMENTS),
        containsInAnyOrder(URN_GROUP_PRODUCTION, URN_GROUP_ANALYSIS));
    // legacy scoped affiliation
    assertThat(claims.getClaim(AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION),
        is("member@iam.example"));
    // voperson scoped affiliation
    assertThat(claims.getClaim(AarcExtraClaimNames.VOPERSON_SCOPED_AFFILIATION),
        is("member@iam.example"));
    // no other aarc claims
    assertNull(claims.getClaim(AarcExtraClaimNames.EDUPERSON_ASSURANCE));
    assertNull(claims.getClaim(AarcExtraClaimNames.VOPERSON_ID));
    assertNull(claims.getClaim(AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION));
  }

  @Test
  public void testAarcProfileAccessTokenWithAllAarcScopes() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "entitlements", "eduperson_assurance", "voperson_id");
    SignedJWT token = SignedJWT.parse(getPasswordToken(scopes).accessToken());

    assertNotNull(token.getJWTClaimsSet().getClaim(VOPERSON_ID));
    assertNotNull(token.getJWTClaimsSet().getClaim(ENTITLEMENTS));
    assertNotNull(token.getJWTClaimsSet().getClaim(EDUPERSON_ASSURANCE));
    assertNotNull(token.getJWTClaimsSet().getClaim(VOPERSON_SCOPED_AFFILIATION));
  }
}
