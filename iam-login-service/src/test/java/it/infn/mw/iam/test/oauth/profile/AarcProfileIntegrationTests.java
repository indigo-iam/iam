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

import static it.infn.mw.iam.core.oauth.profile.aarc.AarcExtraClaimNames.ID_TOKEN_REQUIRED_CLAIMS;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
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
  private static final String URN_GROUP_OPTIONAL = "urn:geant:iam.example:group:Optional";
  private static final String URN_GROUP_PRODUCTION = "urn:geant:iam.example:group:Production";

  private static final String ASSURANCE = "https://refeds.org/assurance";
  private static final String ASSURANCE_VALUE = "https://refeds.org/assurance/IAP/low";

  private static final String EDUPERSON_SCOPED_VALUE = "member@indigo-dc";

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

    assertThat(claims.getClaim("sub"), equalTo(TEST_UUID));
    assertThat(claims.getClaim("eduperson_scoped_affiliation"), nullValue());
    assertThat(claims.getClaim("eduperson_entitlement"), nullValue());

    List<String> groups = Lists.newArrayList(claims.getStringArrayClaim("entitlements"));
    assertThat(groups, hasSize(3));
    assertThat(groups, hasItems(URN_GROUP_ANALYSIS, URN_GROUP_OPTIONAL, URN_GROUP_PRODUCTION));

    Set<String> scopes2 = Sets.newHashSet("openid", "entitlements", "eduperson_entitlement");
    JWTClaimsSet claims2 =
        SignedJWT.parse(getPasswordToken(scopes2).accessToken()).getJWTClaimsSet();

    assertThat(claims2.getClaim("entitlements"), notNullValue());
    assertThat(claims2.getClaim("eduperson_entitlement"), notNullValue());

    Set<String> scopes3 = Sets.newHashSet("openid", "eduperson_entitlement");
    JWTClaimsSet claims3 =
        SignedJWT.parse(getPasswordToken(scopes3).accessToken()).getJWTClaimsSet();

    assertThat(claims3.getClaim("entitlements"), notNullValue());
    assertThat(claims3.getClaim("eduperson_entitlement"), notNullValue());
  }

  @Test
  public void testEdupersonScopedAffiliationScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "eduperson_scoped_affiliation");
    JWTClaimsSet claims = SignedJWT.parse(getPasswordToken(scopes).accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim("sub"), equalTo(TEST_UUID));
    assertThat(claims.getClaim("eduperson_scoped_affiliation"), equalTo(EDUPERSON_SCOPED_VALUE));
    assertThat(claims.getClaim("entitlements"), notNullValue());
    assertThat(claims.getClaim("organization_name"), nullValue());
    assertThat(claims.getClaim("voperson_external_affiliation"), nullValue());
    assertThat(claims.getClaim("voperson_id"), notNullValue());
    assertThat(claims.getClaim("eduperson_assurance"), notNullValue());
  }

  @Test
  public void testEdupersonAssuranceScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "eduperson_assurance");
    JWTClaimsSet claims = SignedJWT.parse(getPasswordToken(scopes).accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim("sub"), equalTo(TEST_UUID));
    assertThat(claims.getClaim("eduperson_scoped_affiliation"), nullValue());
    assertThat(claims.getClaim("entitlements"), notNullValue());
    assertThat(claims.getClaim("organization_name"), nullValue());
    assertThat(claims.getClaim("voperson_external_affiliation"), nullValue());
    assertThat(claims.getClaim("voperson_id"), notNullValue());

    List<String> assurance = Lists.newArrayList(claims.getStringArrayClaim("eduperson_assurance"));

    assertThat(assurance, hasSize(2));
    assertThat(assurance, hasItem(ASSURANCE));
    assertThat(assurance, hasItem(ASSURANCE_VALUE));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testVoPersonIdScope() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid");
    JWTClaimsSet claims = SignedJWT.parse(getPasswordToken(scopes).accessToken()).getJWTClaimsSet();

    assertThat(claims.getClaim("sub"), equalTo(TEST_UUID));
    // required by default
    assertThat(claims.getClaim("voperson_id"), equalTo(TEST_UUID + "@" + ORGANISATION_NAME));
    assertThat(claims.getClaim("eduperson_assurance"), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim("eduperson_assurance"),
        containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE));
    assertThat(claims.getClaim("entitlements"), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim("entitlements"),
        containsInAnyOrder(URN_GROUP_PRODUCTION, URN_GROUP_OPTIONAL, URN_GROUP_ANALYSIS));
    // not required by default
    assertThat(claims.getClaim("aarc_ver"), nullValue());
    assertThat(claims.getClaim("organization_name"), nullValue());
    assertThat(claims.getClaim("eduperson_scoped_affiliation"), nullValue());
    assertThat(claims.getClaim("voperson_external_affiliation"), nullValue());
  }

  @Test
  public void testAarcProfileIntrospect() throws Exception {

    Set<String> scopes = Sets.newHashSet(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL,
        AarcOidcScopes.EDUPERSON_SCOPED_AFFILIATION, AarcOidcScopes.ENTITLEMENTS,
        AarcOidcScopes.EDUPERSON_ASSURANCE);
    String accessToken = getPasswordToken(scopes).accessToken();

    // @formatter:off
    mvc.perform(post(INTROSPECTION_ENDPOINT)
        .with(httpBasic(PROTECTED_RESOURCE_ID, PROTECTED_RESOURCE_SECRET))
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.active", equalTo(true)))
      .andExpect(jsonPath("$.eduperson_scoped_affiliation", equalTo(EDUPERSON_SCOPED_VALUE)))
      .andExpect(jsonPath("$.entitlements", hasSize(equalTo(3))))
      .andExpect(jsonPath("$.entitlements", containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_OPTIONAL, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.eduperson_assurance", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.eduperson_assurance", containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.voperson_id", equalTo(TEST_UUID + "@" + ORGANISATION_NAME)));
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
      .andExpect(jsonPath("$.eduperson_scoped_affiliation", equalTo(EDUPERSON_SCOPED_VALUE)))
      .andExpect(jsonPath("$.eduperson_entitlement", hasSize(equalTo(3))))
      .andExpect(jsonPath("$.eduperson_entitlement", containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_OPTIONAL, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.entitlements", hasSize(equalTo(3))))
      .andExpect(jsonPath("$.entitlements", containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_OPTIONAL, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.eduperson_assurance", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.eduperson_assurance", containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)));
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
      .andExpect(jsonPath("$.eduperson_scoped_affiliation").doesNotExist())
      .andExpect(jsonPath("$.entitlements").exists())
      .andExpect(jsonPath("$.eduperson_assurance").exists())
      .andExpect(jsonPath("$.voperson_id").exists());
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
      .andExpect(jsonPath("$.eduperson_scoped_affiliation").doesNotExist())
      .andExpect(jsonPath("$.entitlements").doesNotExist())
      .andExpect(jsonPath("$.eduperson_assurance").doesNotExist())
      .andExpect(jsonPath("$.voperson_id").doesNotExist());
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
      .andExpect(jsonPath("$.eduperson_scoped_affiliation", equalTo(EDUPERSON_SCOPED_VALUE)))
      .andExpect(jsonPath("$.entitlements", hasSize(equalTo(3))))
      .andExpect(jsonPath("$.entitlements", containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_OPTIONAL, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.eduperson_assurance", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.eduperson_assurance", containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
      .andExpect(jsonPath("$.voperson_id", equalTo(TEST_UUID + "@" + ORGANISATION_NAME)));
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
      .andExpect(jsonPath("$.eduperson_scoped_affiliation", equalTo(EDUPERSON_SCOPED_VALUE)))
      .andExpect(jsonPath("$.entitlements", hasSize(equalTo(3))))
      .andExpect(jsonPath("$.entitlements", containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_OPTIONAL, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.eduperson_assurance", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.eduperson_assurance", containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
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
      .andExpect(jsonPath("$.voperson_id").isNotEmpty())
      .andExpect(jsonPath("$.voperson_id", equalTo(TEST_UUID + "@" + ORGANISATION_NAME)))
      .andExpect(jsonPath("$.eduperson_scoped_affiliation", equalTo(EDUPERSON_SCOPED_VALUE)))
      .andExpect(jsonPath("$.entitlements", hasSize(equalTo(3))))
      .andExpect(jsonPath("$.entitlements", containsInAnyOrder(URN_GROUP_ANALYSIS, URN_GROUP_OPTIONAL, URN_GROUP_PRODUCTION)))
      .andExpect(jsonPath("$.eduperson_assurance", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.eduperson_assurance", containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE)))
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
    assertNotNull(claims.getClaim("sub"));
    ID_TOKEN_REQUIRED_CLAIMS.forEach(c -> assertNotNull(claims.getClaim(c)));
  }

  @Test
  public void testAarcProfileIdTokenWithAarcScope() throws Exception {

    JWTClaimsSet claims = JWTParser.parse(getIdToken("openid aarc")).getJWTClaimsSet();
    assertNotNull(claims.getClaim("sub"));
    assertNotNull(claims.getClaim("voperson_id"));
    assertNotNull(claims.getClaim("entitlements"));
    assertNotNull(claims.getClaim("eduperson_scoped_affiliation"));
    assertNotNull(claims.getClaim("eduperson_assurance"));
    // no external authentication, expected null
    assertNull(claims.getClaim("voperson_external_affiliation"));
    // null legacy claims
    assertNull(claims.getClaim("eduperson_entitlement"));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testAarcProfileIdTokenWithAllSeparatedAarcScopes() throws Exception {

    Set<String> scopes =
        Set.of("openid", "eduperson_scoped_affiliation", "entitlements", "eduperson_assurance");
    JWTClaimsSet claims = JWTParser.parse(getPasswordToken(scopes).idToken()).getJWTClaimsSet();

    assertNotNull(claims.getClaim("sub"));
    assertThat(claims.getClaim("sub"), is(TEST_UUID));
    assertNotNull(claims.getClaim("aud"));
    assertThat(claims.getClaim("aud"), is(List.of(PASSWORD_CLIENT_ID)));
    assertNotNull(claims.getClaim("voperson_id"));
    assertThat(claims.getClaim("voperson_id"), is(TEST_UUID + "@" + ORGANISATION_NAME));
    assertNotNull(claims.getClaim("entitlements"));
    assertThat(claims.getClaim("entitlements"), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim("entitlements"),
        containsInAnyOrder(URN_GROUP_PRODUCTION, URN_GROUP_OPTIONAL, URN_GROUP_ANALYSIS));
    assertNotNull(claims.getClaim("eduperson_scoped_affiliation"));
    assertThat(claims.getClaim("eduperson_scoped_affiliation"), is(EDUPERSON_SCOPED_VALUE));
    assertNotNull(claims.getClaim("eduperson_assurance"));
    assertThat(claims.getClaim("eduperson_assurance"), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim("eduperson_assurance"),
        containsInAnyOrder(ASSURANCE, ASSURANCE_VALUE));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testAarcProfileIdTokenWithLegacyAarcScopes() throws Exception {

    Set<String> scopes = Set.of(OidcScopes.OPENID, AarcOidcScopes.EDUPERSON_ENTITLEMENT);
    JWTClaimsSet claims = JWTParser.parse(getPasswordToken(scopes).idToken()).getJWTClaimsSet();

    assertThat(claims.getClaim("sub"), is(TEST_UUID));
    assertThat(claims.getClaim("aud"), is(List.of(PASSWORD_CLIENT_ID)));
    // legacy entitlements
    assertThat(claims.getClaim("eduperson_entitlement"), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim("eduperson_entitlement"),
        containsInAnyOrder(URN_GROUP_PRODUCTION, URN_GROUP_OPTIONAL, URN_GROUP_ANALYSIS));
    // entitlements
    assertThat(claims.getClaim("entitlements"), instanceOf(ArrayList.class));
    assertThat((ArrayList<String>) claims.getClaim("entitlements"),
        containsInAnyOrder(URN_GROUP_PRODUCTION, URN_GROUP_OPTIONAL, URN_GROUP_ANALYSIS));
    assertNull(claims.getClaim("eduperson_scoped_affiliation"));
    assertNotNull(claims.getClaim("eduperson_assurance"));
    assertNotNull(claims.getClaim("voperson_id"));
    assertNull(claims.getClaim("voperson_external_affiliation"));
  }

  @Test
  public void testAarcProfileAccessTokenWithAllAarcScopes() throws Exception {

    Set<String> scopes = Sets.newHashSet("openid", "profile", "email",
        "eduperson_scoped_affiliation", "entitlements", "eduperson_assurance");
    SignedJWT token = SignedJWT.parse(getPasswordToken(scopes).accessToken());

    assertNotNull(token.getJWTClaimsSet().getClaim("voperson_id"));
    assertNotNull(token.getJWTClaimsSet().getClaim("entitlements"));
    assertNotNull(token.getJWTClaimsSet().getClaim("eduperson_assurance"));
    assertNotNull(token.getJWTClaimsSet().getClaim("eduperson_scoped_affiliation"));
  }
}
