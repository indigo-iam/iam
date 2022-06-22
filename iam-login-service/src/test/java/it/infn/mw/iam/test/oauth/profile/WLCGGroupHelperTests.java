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

import static com.google.common.collect.Sets.newLinkedHashSet;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WLCGGroupHelper.OPTIONAL_GROUP_LABEL;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.wlcg.WLCGGroupHelper;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@SuppressWarnings("deprecation")
@RunWith(MockitoJUnitRunner.class)
public class WLCGGroupHelperTests {

  @Mock
  OAuth2AccessTokenEntity token;

  @Mock
  IamUserInfo userInfo;

  WLCGGroupHelper helper = new WLCGGroupHelper();

  @Before
  public void setup() {
    when(userInfo.getGroups()).thenReturn(Collections.emptySet());
    when(token.getScope()).thenReturn(newLinkedHashSet(asList("openid")));
  }


  protected IamGroup buildGroup(String name) {
    IamGroup g = new IamGroup();
    g.setUuid(UUID.randomUUID().toString());
    g.setName(name);

    return g;
  }

  protected IamGroup buildOptionalGroup(String name) {
    IamGroup g = buildGroup(name);
    g.setLabels(Sets.newHashSet(OPTIONAL_GROUP_LABEL));
    return g;
  }



  @Test
  public void testNoWLCGGroupScope() {
    assertThat(helper.resolveGroups(token, userInfo), empty());
  }

  @Test
  public void testWLCGGroupScopeNoGroups() {
    when(token.getScope()).thenReturn(newLinkedHashSet(asList("openid", "wlcg.groups")));
    assertThat(helper.resolveGroups(token, userInfo), empty());
  }

  @Test
  public void testNoWLCGGroupScopeNoGroups() {
    when(token.getScope()).thenReturn(newLinkedHashSet(asList("openid", "profile")));
    assertThat(helper.resolveGroups(token, userInfo), empty());
  }

  @Test
  public void testWLCGGroupScopeAllDefaultGroupsReturned() {

    IamGroup g1 = buildGroup("g1");
    IamGroup g2 = buildGroup("g2");
    IamGroup g3 = buildOptionalGroup("g3");

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g1, g2, g3));

    when(token.getScope()).thenReturn(newLinkedHashSet(asList("openid", "wlcg.groups")));

    Set<IamGroup> groups = helper.resolveGroups(token, userInfo);
    assertThat(groups, hasSize(2));
    assertThat(groups, hasItem(g1));
    assertThat(groups, hasItem(g2));
  }

  @Test
  public void testWLCGGroupScopeAllOptionalGroups() {

    IamGroup g1 = buildOptionalGroup("g1");
    IamGroup g2 = buildOptionalGroup("g2");
    IamGroup g3 = buildOptionalGroup("g3");

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g1, g2, g3));

    when(token.getScope()).thenReturn(newLinkedHashSet(asList("openid", "wlcg.groups")));

    Set<IamGroup> groups = helper.resolveGroups(token, userInfo);
    assertThat(groups, empty());
  }

  @Test
  public void testWLCGGroupOrdering() {

    IamGroup g1 = buildGroup("g1");
    IamGroup g2 = buildGroup("g2");
    IamGroup g3 = buildOptionalGroup("g3");

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g1, g2, g3));

    when(token.getScope())
      .thenReturn(newLinkedHashSet(asList("openid", "wlcg.groups:/g3", "wlcg.groups")));

    List<IamGroup> groupList = Lists.newArrayList(helper.resolveGroups(token, userInfo));

    assertThat(groupList, hasSize(3));
    assertThat(groupList.get(0), is(g3));
    assertThat(groupList.get(1), is(g1));
    assertThat(groupList.get(2), is(g2));

  }

  @Test
  public void testWLCGGroupOrdering2() {

    IamGroup g1 = buildGroup("g1");
    IamGroup g2 = buildGroup("g2");
    IamGroup g3 = buildOptionalGroup("g3");

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g1, g2, g3));

    when(token.getScope())
      .thenReturn(newLinkedHashSet(asList("openid", "wlcg.groups", "wlcg.groups:/g3")));

    List<IamGroup> groupList = Lists.newArrayList(helper.resolveGroups(token, userInfo));

    assertThat(groupList, hasSize(3));
    assertThat(groupList.get(0), is(g1));
    assertThat(groupList.get(1), is(g2));
    assertThat(groupList.get(2), is(g3));

  }


  @Test
  public void testWLCGDefaultGroupsAlwaysIncludedInTail() {

    IamGroup g1 = buildGroup("g1");
    IamGroup g2 = buildGroup("g2");
    IamGroup g3 = buildOptionalGroup("g3");

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g1, g2, g3));

    when(token.getScope()).thenReturn(newLinkedHashSet(asList("openid", "wlcg.groups:/g3")));

    List<IamGroup> groupList = Lists.newArrayList(helper.resolveGroups(token, userInfo));

    assertThat(groupList, hasSize(3));
    assertThat(groupList.get(0), is(g3));
    assertThat(groupList.get(1), is(g1));
    assertThat(groupList.get(2), is(g2));

  }


  @Test
  public void testRequestScopeOrderingIsRespected() {

    IamGroup g1 = buildGroup("g1");
    IamGroup g2 = buildGroup("g2");
    IamGroup g3 = buildOptionalGroup("g3");
    IamGroup g4 = buildOptionalGroup("g4");

    when(userInfo.getGroups()).thenReturn(Sets.newHashSet(g1, g2, g3, g4));

    when(token.getScope())
      .thenReturn(newLinkedHashSet(asList("openid", "wlcg.groups:/g4", "wlcg.groups:/g2")));

    List<IamGroup> groupList = Lists.newArrayList(helper.resolveGroups(token, userInfo));

    assertThat(groupList, hasSize(3));
    assertThat(groupList.get(0), is(g4));
    assertThat(groupList.get(1), is(g2));
    assertThat(groupList.get(2), is(g1));
  }

  @Test
  public void testValidGroupScopeRegexp() {

    Stream<String> validGroupScopes = Stream.of("wlcg.groups", "wlcg.groups:/example",
        "wlcg.groups:/test.vo/what-ever/happens_to_you");

    validGroupScopes.forEach(helper::validateGroupScope);
  }

  @Test
  public void testInvalidGroupScopes() {
    Stream<String> invalidGroupScopes =
        Stream.of("wlcg.groups:", "wlcg.groups:example", "wlcg.groups://");

    invalidGroupScopes.forEach(s -> {
      try {
        helper.validateGroupScope(s);
        throw new AssertionError("Invalid scope not detected: " + s);
      } catch (InvalidScopeException e) {
        // expected
      }
    });
  }
}
