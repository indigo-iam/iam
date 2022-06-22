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

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ScimGroupManagerTests {

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAuthoritiesRepository authoritiesRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private UserConverter userConverter;

  private static final String GROUP_URI = ScimUtils.getGroupsLocation();

  private static final String TEST_001_GROUP_ID = "c617d586-54e6-411d-8e38-649677980001";
  private static final String TEST_002_GROUP_ID = "c617d586-54e6-411d-8e38-649677980002";

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
  @WithMockUser(username = "test", roles = {"USER", "GM:" + TEST_001_GROUP_ID})
  public void groupManagerCanSeeGroup() throws Exception {
    mvc.perform(get(GROUP_URI + "/{uuid}", TEST_001_GROUP_ID).content(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andExpect(jsonPath("$.id", equalTo(TEST_001_GROUP_ID)));

    mvc.perform(get(GROUP_URI + "/{uuid}", TEST_002_GROUP_ID).content(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER", "GM:" + TEST_001_GROUP_ID})
  public void groupManagerCanDeleteGroup() throws Exception {

    mvc.perform(delete(GROUP_URI + "/{uuid}", TEST_001_GROUP_ID).content(SCIM_CONTENT_TYPE))
      .andExpect(status().isNoContent());

    mvc.perform(delete(GROUP_URI + "/{uuid}", TEST_002_GROUP_ID).content(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void groupCreationCreatesGroupManagerAuthority() throws Exception {
    String name = "test-gm-creation";
    ScimGroup group = ScimGroup.builder(name).build();

    String res = mvc
      .perform(
          post(GROUP_URI).contentType(SCIM_CONTENT_TYPE).content(mapper.writeValueAsString(group)))
      .andExpect(status().isCreated())
      .andReturn()
      .getResponse()
      .getContentAsString();

    ScimGroup createdGroup = mapper.readValue(res, ScimGroup.class);

    String authority = String.format("ROLE_GM:%s", createdGroup.getId());

    assertThat(authoritiesRepo.findByAuthority(authority).isPresent(), is(true));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void groupDeletionRemovesGroupManagerAuthority() throws Exception {
    String name = "test-gm-deletion";

    ScimGroup group = ScimGroup.builder(name).build();

    String res = mvc
      .perform(
          post(GROUP_URI).contentType(SCIM_CONTENT_TYPE).content(mapper.writeValueAsString(group)))
      .andExpect(status().isCreated())
      .andReturn()
      .getResponse()
      .getContentAsString();

    ScimGroup createdGroup = mapper.readValue(res, ScimGroup.class);
    String authority = String.format("ROLE_GM:%s", createdGroup.getId());

    IamAuthority auth = authoritiesRepo.findByAuthority(authority)
      .orElseThrow(() -> new AssertionError("Expected authority not found"));

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user test not found"));

    testAccount.getAuthorities().add(auth);

    accountRepo.save(testAccount);

    mvc.perform(delete(GROUP_URI + "/{uuid}", createdGroup.getId()))
      .andExpect(status().isNoContent());

    assertThat(accountRepo.findByAuthority(authority).isEmpty(), is(true));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER", "GM:" + TEST_001_GROUP_ID})
  public void groupManagerCanAddAndRemoveMembers() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user test not found"));

    ScimUser scimTestUser = userConverter.dtoFromEntity(testAccount);
    List<ScimUser> members = Lists.newArrayList();
    members.add(scimTestUser);

    ScimGroupPatchRequest patchAddReq =
        ScimGroupPatchRequest.builder().add(TestUtils.buildScimMemberRefList(members)).build();


    ScimGroupPatchRequest patchRemReq =
        ScimGroupPatchRequest.builder().remove(TestUtils.buildScimMemberRefList(members)).build();

    mvc
      .perform(patch(GROUP_URI + "/{uuid}", TEST_001_GROUP_ID).contentType(SCIM_CONTENT_TYPE)
        .content(mapper.writeValueAsString(patchAddReq)))
      .andExpect(status().isNoContent());

    mvc
      .perform(patch(GROUP_URI + "/{uuid}", TEST_002_GROUP_ID).contentType(SCIM_CONTENT_TYPE)
        .content(mapper.writeValueAsString(patchAddReq)))
      .andExpect(status().isForbidden());
    
    mvc
    .perform(patch(GROUP_URI + "/{uuid}", TEST_001_GROUP_ID).contentType(SCIM_CONTENT_TYPE)
      .content(mapper.writeValueAsString(patchRemReq)))
    .andExpect(status().isNoContent());
    
  }
}
