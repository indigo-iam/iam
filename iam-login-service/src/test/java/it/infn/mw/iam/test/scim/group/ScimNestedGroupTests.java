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
package it.infn.mw.iam.test.scim.group;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimIndigoGroup;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ScimNestedGroupTests {

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateNewChildGroup() throws Exception {

    ScimGroup animals = createGroup("animals");
    assertNotNull(animals);

    ScimGroup mammals = createGroup("mammals", animals);
    assertNotNull(mammals);

    assertEquals(animals.getId(), mammals.getIndigoGroup().getParentGroup().getValue());
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateGroupWithNotExistingParent() throws Exception {
    String uuid = "fake-group-very-long-uuid";
    ScimGroupRef fakeGroupRef = ScimGroupRef.builder()
      .display("fake group")
      .value(uuid)
      .ref(scimResourceLocationProvider.groupLocation(uuid))
      .build();

    ScimIndigoGroup scimFakeParentGroup =
        ScimIndigoGroup.getBuilder().parentGroup(fakeGroupRef).build();

    // @formatter:off
    mvc.perform(post("/scim/Groups")
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(ScimGroup.builder("mammals").indigoGroup(scimFakeParentGroup).build())))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.status", equalTo("404")))
      .andExpect(jsonPath("$.detail", equalTo(format("Parent group '%s' not found", uuid))));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testDeleteParentGroupWithChildren() throws Exception {
    ScimGroup animals = createGroup("animals");
    createGroup("mammals", animals);

    // @formatter:off
    mvc.perform(delete(animals.getMeta().getLocation()))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status", equalTo("400")))
      .andExpect(jsonPath("$.detail", equalTo("Group is not empty")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testDeleteChildGroup() throws Exception {
    ScimGroup animals = createGroup("animals");
    ScimGroup mammals = createGroup("mammals", animals);

    // @formatter:off
    mvc.perform(delete(mammals.getMeta().getLocation()))
      .andExpect(status().isNoContent());
    // @formatter:on

    // @formatter:off
    mvc.perform(get("/scim/Groups/{id}", animals.getId()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(animals.getId())))
      .andExpect(jsonPath("$.members").doesNotExist());
    // @formatter:on
  }


  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testGetChildGroup() throws Exception {
    ScimGroup animals = createGroup("animals");
    ScimGroup mammals = createGroup("mammals", animals);

    // @formatter:off
    mvc.perform(get("/scim/Groups/{id}", mammals.getId()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(mammals.getId())))
      .andExpect(jsonPath("$.displayName", equalTo(mammals.getDisplayName())))
      .andExpect(jsonPath("$."+INDIGO_GROUP_SCHEMA+".parentGroup.display", equalTo(animals.getDisplayName())))
      .andExpect(jsonPath("$."+INDIGO_GROUP_SCHEMA+".parentGroup.value", equalTo(animals.getId())))
      .andExpect(jsonPath("$."+INDIGO_GROUP_SCHEMA+".parentGroup.$ref", equalTo(animals.getMeta().getLocation())));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateGroupWithASlashIntoDisplayName() throws Exception {
    ScimGroup group = ScimGroup.builder("te/st").build();

    // @formatter:off
    mvc.perform(post("/scim/Groups").contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(group)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.detail", equalTo("Group displayName cannot contain a slash character")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateTwoGroupsWithSameNameButDifferentParent() throws Exception {
    ScimGroup cms = createGroup("cms");
    ScimGroup alice = createGroup("alice");

    ScimGroup cmsTest = createGroup("test", cms);
    assertNotNull(cmsTest);
    assertThat(cmsTest.getDisplayName(), equalTo("cms/test"));

    ScimGroup aliceTest = createGroup("test", alice);
    assertNotNull(aliceTest);
    assertThat(aliceTest.getDisplayName(), equalTo("alice/test"));
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateTwoGroupsWithSameNameAndSameParent() throws Exception {
    ScimGroup cms = createGroup("cms");

    ScimGroup cmsTest = createGroup("test", cms);
    assertNotNull(cmsTest);
    assertThat(cmsTest.getDisplayName(), equalTo("cms/test"));

    // @formatter:off
    mvc.perform(post("/scim/Groups").contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(buildGroupObject("test", cms))))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail", equalTo("Duplicated group 'cms/test'")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateGroupWithFullNameTooLong() throws Exception {
    String name = "group_with_fifty_characters_name_has_a_long_name_";
    ScimGroup group = createGroup(name);

    for (int i = 0; i < 9; i++) {
      group = createGroup(name + i, group);
    }

    group = buildGroupObject(name, group);

    // @formatter:off
    mvc.perform(post("/scim/Groups").contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(group)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.detail", equalTo("Group displayName length cannot exceed 512 characters")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateGroupWithNameTooLong() throws Exception {
    ScimGroup group =
        buildGroupObject("group_with_name_longer_than_fifty_characters_is_not_allowed", null);

    assertNotNull(group);

    // @formatter:off
    mvc.perform(post("/scim/Groups").contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(group)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.detail", equalTo("Group name length cannot exceed 50 characters")));
    // @formatter:on
  }

  private ScimGroup createGroup(String name) throws Exception {
    return createGroup(name, null);
  }

  private ScimGroup createGroup(String name, ScimGroup parent) throws Exception {
    ScimGroup group = buildGroupObject(name, parent);

    String response = mvc
      .perform(post("/scim/Groups").contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(group)))
      .andExpect(status().isCreated())
      .andReturn()
      .getResponse()
      .getContentAsString();

    return objectMapper.readValue(response, ScimGroup.class);
  }

  private ScimGroup buildGroupObject(String name, ScimGroup parent) {
    ScimGroup group = ScimGroup.builder(name).build();
    if (parent != null) {
      ScimGroupRef parentGroupRef = ScimGroupRef.builder()
        .display(parent.getDisplayName())
        .value(parent.getId())
        .ref(scimResourceLocationProvider.groupLocation(parent.getId()))
        .build();

      ScimIndigoGroup parentIndigoGroup =
          ScimIndigoGroup.getBuilder().parentGroup(parentGroupRef).build();

      group = ScimGroup.builder(name).indigoGroup(parentIndigoGroup).build();
    }
    return group;
  }

}
