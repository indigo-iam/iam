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

import static java.util.Collections.emptySet;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcScopeClaimTranslationService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@SuppressWarnings({"deprecation", "unchecked"})
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {
    // @formatter:off
  "iam.aarc-profile.urn-delegated-namespace=projectescape.eu",
  "iam.aarc-profile.urn-subnamespaces=sub mission",
    // @formatter:on
    })
@AutoConfigureMockMvc
@Transactional
class AarcClaimValueHelperTests {

  @Autowired
  private IamProperties properties;

  @Autowired
  private SshKeyConverter sshConverter;

  @Autowired
  private AttributeMapHelper attrHelper;

  @Autowired
  private IamGroupService groupService;

  private IamUserInfo userInfo = mock(IamUserInfo.class);
  private AarcClaimValueHelper helper;
  private AarcScopeClaimTranslationService claimService = new AarcScopeClaimTranslationService();

  @BeforeEach
  void setup() {
    helper = new AarcClaimValueHelper(properties, sshConverter, attrHelper, claimService);
    when(userInfo.getGroups()).thenReturn(Collections.emptySet());
  }

  @Test
  void testEmptyGroupsUrnEncode() {

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet());

    Set<String> urns = helper.resolveGroups(userInfo);
    assertThat(urns, hasSize(0));
  }

  @Test
  void testGroupUrnEncode() {

    String s = "urn:geant:projectescape.eu:sub:mission:group:test";

    IamGroup g = new IamGroup();
    g.setName("test");
    groupService.createGroup(g);

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g));

    Set<String> urns = helper.resolveGroups(userInfo);
    assertThat(urns, hasSize(1));
    assertThat(urns, hasItem(s));
  }

  @Test
  void testGroupHierarchyUrnEncode() {

    String parentUrn = "urn:geant:projectescape.eu:sub:mission:group:parent";
    String childUrn = "urn:geant:projectescape.eu:sub:mission:group:parent:child";
    String grandchildUrn = "urn:geant:projectescape.eu:sub:mission:group:parent:child:grandchild";

    IamGroup parent = new IamGroup();
    parent.setName("parent");
    groupService.createGroup(parent);

    IamGroup child = new IamGroup();
    child.setName("parent/child");
    child.setParentGroup(parent);
    groupService.createGroup(child);

    IamGroup grandChild = new IamGroup();
    grandChild.setName("parent/child/grandchild");
    grandChild.setParentGroup(child);
    groupService.createGroup(grandChild);

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(parent, child, grandChild));

    Set<String> urns = helper.resolveGroups(userInfo);
    assertThat(urns, hasSize(3));
    assertThat(urns, hasItem(parentUrn));
    assertThat(urns, hasItem(childUrn));
    assertThat(urns, hasItem(grandchildUrn));
  }

  @Test
  void testEmptyGroupListEncode() {
    when(userInfo.getGroups()).thenReturn(emptySet());
    Set<String> urns = helper.resolveGroups(userInfo);
    assertThat(urns, empty());
  }

  @Test
  void testResolveScopedClaimsUseConfiguredScopeDomainWhenPresent() {
    properties.setIssuer("https://issuer.example");
    properties.getAarcProfile().setAffiliationScope("https://scope.example");

    IamAccount account = mock(IamAccount.class);
    IamUserInfo accountUserInfo = mock(IamUserInfo.class);

    when(account.getUserInfo()).thenReturn(accountUserInfo);
    when(accountUserInfo.getSub()).thenReturn("test-subject");

    String vopersonId =
        (String) helper.resolveClaim(AarcExtraClaimNames.VOPERSON_ID, null, Optional.of(account));
    String scopedAffiliation = (String) helper
      .resolveClaim(AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION, null, Optional.of(account));

    assertEquals("test-subject@https://scope.example", vopersonId);
    assertEquals("member@https://scope.example", scopedAffiliation);
  }

  @Test
  void testResolveScopedClaimsUseIssuerWhenScopeDomainMissing() {
    properties.setIssuer("https://issuer.example");
    properties.getAarcProfile().setAffiliationScope(null);

    IamAccount account = mock(IamAccount.class);
    IamUserInfo accountUserInfo = mock(IamUserInfo.class);

    when(account.getUserInfo()).thenReturn(accountUserInfo);
    when(accountUserInfo.getSub()).thenReturn("test-subject");

    String vopersonId =
        (String) helper.resolveClaim(AarcExtraClaimNames.VOPERSON_ID, null, Optional.of(account));
    String scopedAffiliation = (String) helper
      .resolveClaim(AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION, null, Optional.of(account));

    assertEquals("test-subject@https://issuer.example/", vopersonId);
    assertEquals("member@https://issuer.example/", scopedAffiliation);
  }

  @Test
  void testResolveScopedAffiliations() {
    OAuth2Authentication auth = mock(OAuth2Authentication.class);

    Map<String, String> additionalInfo = new HashMap<>();
    additionalInfo.put("EPSA", "external@test.org");

    SavedUserAuthentication savedAuth = new SavedUserAuthentication();
    savedAuth.setSourceClass(OidcExternalAuthenticationToken.class.getName());
    savedAuth.setAdditionalInfo(additionalInfo);

    when(auth.getUserAuthentication()).thenReturn(savedAuth);

    IamAccount account = mock(IamAccount.class);
    IamUserInfo accountUserInfo = mock(IamUserInfo.class);

    when(account.getAffiliation()).thenReturn("member");
    when(account.getUserInfo()).thenReturn(accountUserInfo);
    when(accountUserInfo.getAffiliation()).thenReturn("member");

    Set<String> result = (Set<String>) helper
      .resolveClaim(AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION, auth, Optional.of(account));

    assertThat(result, hasSize(2));
    assertThat(result, hasItem("member@" + properties.getAarcProfile().getAffiliationScope()));
    assertThat(result, hasItem("external@test.org"));
  }

  @Test
  void testResolveScopedAffiliationsWithNullAffiliation() {
    OAuth2Authentication auth = mock(OAuth2Authentication.class);

    Map<String, String> additionalInfo = new HashMap<>();
    additionalInfo.put("EPSA", "external@test.org");

    SavedUserAuthentication savedAuth = new SavedUserAuthentication();
    savedAuth.setSourceClass(OidcExternalAuthenticationToken.class.getName());
    savedAuth.setAdditionalInfo(additionalInfo);

    when(auth.getUserAuthentication()).thenReturn(savedAuth);

    IamAccount account = mock(IamAccount.class);
    IamUserInfo accountUserInfo = mock(IamUserInfo.class);

    when(account.getUserInfo()).thenReturn(accountUserInfo);

    Set<String> result = (Set<String>) helper
      .resolveClaim(AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION, auth, Optional.of(account));

    assertThat(result, hasSize(1));
    assertThat(result, hasItem("external@test.org"));
  }

  @Test
  void testResolveAssuranceInfo() {
    OAuth2Authentication auth = mock(OAuth2Authentication.class);

    Map<String, String> additionalInfo = new HashMap<>();
    additionalInfo.put("urn:oid:1.3.6.1.4.1.5923.1.1.1.11",
        "https://refeds.org/assurance/IAP/medium");

    SavedUserAuthentication savedAuth = new SavedUserAuthentication();
    savedAuth.setSourceClass(OidcExternalAuthenticationToken.class.getName());
    savedAuth.setAdditionalInfo(additionalInfo);

    when(auth.getUserAuthentication()).thenReturn(savedAuth);

    IamAccount account = mock(IamAccount.class);

    Set<String> result = (Set<String>) helper.resolveClaim(AarcExtraClaimNames.EDUPERSON_ASSURANCE,
        auth, Optional.of(account));

    assertThat(result, hasSize(3));
    assertThat(result, hasItem("https://refeds.org/assurance/IAP/medium"));
    assertThat(result, hasItem("https://refeds.org/assurance/IAP/low"));
    assertThat(result, hasItem("https://refeds.org/assurance"));
  }

  @Test
  void testResolveSchacHomeOrganization() {
    OAuth2Authentication auth = mock(OAuth2Authentication.class);

    Map<String, String> additionalInfo = new HashMap<>();
    additionalInfo.put("urn:oid:1.3.6.1.4.1.25178.1.2.9", "infn.it");

    SavedUserAuthentication savedAuth = new SavedUserAuthentication();
    savedAuth.setSourceClass(OidcExternalAuthenticationToken.class.getName());
    savedAuth.setAdditionalInfo(additionalInfo);

    when(auth.getUserAuthentication()).thenReturn(savedAuth);

    IamAccount account = mock(IamAccount.class);

    String result = (String) helper.resolveClaim(AarcExtraClaimNames.SCHAC_HOME_ORGANIZATION, auth,
        Optional.of(account));

    assertEquals("infn.it", result);
  }
}
