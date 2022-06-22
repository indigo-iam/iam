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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {
  // @formatter:off
  "iam.host=example.org",
  "iam.organisation.name=org",
  "iam.aarc-profile.urn-namespace=example:iam:test",
  // @formatter:on
})
@Transactional
public class AarcClaimValueHelperTests {


  @Autowired
  private AarcClaimValueHelper helper;

  @Autowired
  private IamGroupService groupService;

  IamUserInfo userInfo = mock(IamUserInfo.class);

  @Before
  public void setup() {
    when(userInfo.getGroups()).thenReturn(Collections.emptySet());
  }


  @Test
  public void testEmptyGroupsUrnEncode() {

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet());

    Set<String> urns = helper.resolveGroups(userInfo);
    assertThat(urns, hasSize(0));
  }

  @Test
  public void testGroupUrnEncode() {

    String s = "urn:example:iam:test:group:test#example.org";

    IamGroup g = new IamGroup();
    g.setName("test");
    groupService.createGroup(g);


    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g));

    Set<String> urns = helper.resolveGroups(userInfo);
    assertThat(urns, hasSize(1));
    assertThat(urns, hasItem(s));
  }

  @Test
  public void testGroupHierarchyUrnEncode() {

    String parentUrn = "urn:example:iam:test:group:parent#example.org";
    String childUrn = "urn:example:iam:test:group:parent:child#example.org";
    String grandchildUrn = "urn:example:iam:test:group:parent:child:grandchild#example.org";

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
  public void testEmptyGroupListEncode() {
    when(userInfo.getGroups()).thenReturn(emptySet());
    Set<String> urns = helper.resolveGroups(userInfo);
    assertThat(urns, empty());
  }
}
