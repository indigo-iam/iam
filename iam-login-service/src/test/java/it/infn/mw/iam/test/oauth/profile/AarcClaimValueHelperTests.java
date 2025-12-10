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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcScopeClaimTranslationService;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {
// @formatter:off
  "iam.aarc-profile.urn-delegated-namespace=projectescape.eu",
  "iam.aarc-profile.urn-subnamespaces=sub mission",
  // @formatter:on
})
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
}
