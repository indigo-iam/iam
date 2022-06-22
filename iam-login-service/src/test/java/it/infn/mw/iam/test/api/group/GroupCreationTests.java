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
package it.infn.mw.iam.test.api.group;

import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.common.GroupDTO;
import it.infn.mw.iam.api.scope_policy.GroupRefDTO;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class GroupCreationTests {

  private static final String NEW_GROUP_NAME = "brand-new-group";
  private static final String NEW_GROUP_DESC = "A description";

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private ObjectMapper mapper;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  @Test
  public void createGroupRequiresAuthenticatedUser() throws Exception {

    GroupDTO model = GroupDTO.builder().name(NEW_GROUP_NAME).description(NEW_GROUP_DESC).build();

    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isUnauthorized());
  }


  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void createGroupFailsForNonAdminUser() throws Exception {

    GroupDTO model = GroupDTO.builder().name(NEW_GROUP_NAME).description(NEW_GROUP_DESC).build();

    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void createGroupSucceedsForAdminUser() throws Exception {

    GroupDTO model = GroupDTO.builder().name(NEW_GROUP_NAME).description(NEW_GROUP_DESC).build();

    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isCreated())
      .andExpect(jsonPath("$.id").exists())
      .andExpect(jsonPath("$.name", is(NEW_GROUP_NAME)))
      .andExpect(jsonPath("$.description", is(NEW_GROUP_DESC)));


    IamGroup g = groupRepo.findByName(NEW_GROUP_NAME)
      .orElseThrow(assertionError("Expected group not found"));
    GroupRefDTO ref = new GroupRefDTO();
    ref.setUuid(g.getUuid());

    GroupDTO child = GroupDTO.builder().name("child").parent(ref).build();

    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(child))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isCreated())
      .andExpect(jsonPath("$.id").exists())
      .andExpect(jsonPath("$.name", is(format("%s/%s", NEW_GROUP_NAME, child.getName()))))
      .andExpect(jsonPath("$.parent.uuid", is(g.getUuid())));

  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void slashNotAllowedInGroupName() throws Exception {
    GroupDTO model = GroupDTO.builder().name("ihave/agroupname").build();

    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("invalid name")));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void blankNameNotAllowed() throws Exception {

    GroupDTO blanky = GroupDTO.builder().name("").build();
    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(blanky))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("invalid name")));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void longCompositeNameNotAllowed() throws Exception {
    StringBuilder longNameBuilder = new StringBuilder();
    for (int i = 0; i < 510; i++) {
      longNameBuilder.append('a');
    }

    String longName = longNameBuilder.toString();
    GroupDTO model = GroupDTO.builder().name(longName.toString()).build();

    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    IamGroup g =
        groupRepo.findByName(longName).orElseThrow(assertionError("Expected group not found"));
    GroupRefDTO ref = new GroupRefDTO();
    ref.setUuid(g.getUuid());

    GroupDTO child = GroupDTO.builder().name("child").parent(ref).build();

    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(child))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("group name too long")));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void longDescriptionNotAllowed() throws Exception {
    StringBuilder longNameBuilder = new StringBuilder();

    for (int i = 0; i < 513; i++) {
      longNameBuilder.append('a');
    }

    GroupDTO model =
        GroupDTO.builder().name(NEW_GROUP_NAME).description(longNameBuilder.toString()).build();
    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(
          jsonPath("$.error", containsString("description cannot be longer than 512 chars")));

  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void longDescriptionNotAllowedInUpdate() throws Exception {
    StringBuilder longNameBuilder = new StringBuilder();

    for (int i = 0; i < 513; i++) {
      longNameBuilder.append('a');
    }

    GroupDTO model = GroupDTO.builder().name(NEW_GROUP_NAME).build();
    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());


    IamGroup g = groupRepo.findByName(NEW_GROUP_NAME)
      .orElseThrow(assertionError("Expected group not found"));

    GroupDTO desc = GroupDTO.builder().description(longNameBuilder.toString()).build();
    mvc
      .perform(MockMvcRequestBuilders.put("/iam/group/{id}", g.getUuid())
        .content(mapper.writeValueAsBytes(desc))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(
          jsonPath("$.error", containsString("description cannot be longer than 512 chars")));

  }


  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void adminCanUpdateDescription() throws Exception {

    GroupDTO model = GroupDTO.builder().name(NEW_GROUP_NAME).build();
    mvc
      .perform(post("/iam/group").content(mapper.writeValueAsBytes(model))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());


    IamGroup g = groupRepo.findByName(NEW_GROUP_NAME)
      .orElseThrow(assertionError("Expected group not found"));

    GroupDTO desc = GroupDTO.builder().description(NEW_GROUP_DESC).build();
    mvc
      .perform(put("/iam/group/{id}", g.getUuid()).content(mapper.writeValueAsBytes(desc))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.description", is(NEW_GROUP_DESC)));

  }


  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void userCannotUpdateDescription() throws Exception {

    IamGroup g =
        groupRepo.findByName("Production").orElseThrow(assertionError("Expected group not found"));

    GroupDTO desc = GroupDTO.builder().description(NEW_GROUP_DESC).build();

    mvc.perform(put("/iam/group/{id}", g.getUuid()).content(mapper.writeValueAsBytes(desc))
      .contentType(APPLICATION_JSON)).andExpect(status().isForbidden());
  }


  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void nonExistingGroupCorrectlyHandled() throws Exception {

    GroupDTO desc = GroupDTO.builder().description(NEW_GROUP_DESC).build();

    mvc
      .perform(put("/iam/group/{id}", UUID.randomUUID().toString())
        .content(mapper.writeValueAsBytes(desc))
        .contentType(APPLICATION_JSON))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", containsString("Group not found")));
  }



}
