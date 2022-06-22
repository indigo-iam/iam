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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
import org.springframework.test.web.servlet.ResultMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.common.AttributeDTO;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class GroupAttributeTests {

  public static final ResultMatcher UNAUTHORIZED = status().isUnauthorized();
  public static final ResultMatcher FORBIDDEN = status().isForbidden();
  public static final ResultMatcher NOT_FOUND = status().isNotFound();

  public static final String TEST_001_GROUP = "Test-001";

  public static final String EXPECTED_GROUP_NOT_FOUND = "Expected group not found";

  public static final String ATTR_NAME = "attr.example";
  public static final String ATTR_VALUE = "somevalue";

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
  public void managingAttributesRequiresAuthenticatedUser() throws Exception {

    IamGroup testGroup =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(get("/iam/group/{id}/attributes", testGroup.getUuid())).andExpect(UNAUTHORIZED);

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc.perform(
        put("/iam/group/{id}/attributes", testGroup.getUuid()).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(attr)))
      .andExpect(UNAUTHORIZED);

    mvc.perform(delete("/iam/group/{id}/attributes", testGroup.getUuid()).param("name", ATTR_NAME))
      .andExpect(UNAUTHORIZED);
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void managingAttributesRequiresPrivilegedUser() throws Exception {

    IamGroup testGroup =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(get("/iam/group/{id}/attributes", testGroup.getUuid())).andExpect(FORBIDDEN);

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc.perform(
        put("/iam/group/{id}/attributes", testGroup.getUuid()).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(attr)))
      .andExpect(FORBIDDEN);

    mvc.perform(delete("/iam/group/{id}/attributes", testGroup.getUuid()).param("name", ATTR_NAME))
      .andExpect(FORBIDDEN);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void gettingAttributesWorksForAdminUser() throws Exception {

    IamGroup testGroup =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(get("/iam/group/{id}/attributes", testGroup.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").isEmpty());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void setAttributeWorks() throws Exception {
    IamGroup testGroup =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc.perform(
        put("/iam/group/{id}/attributes", testGroup.getUuid()).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(attr)))
      .andExpect(status().isOk());

    mvc.perform(get("/iam/group/{id}/attributes", testGroup.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$[0].name", is(ATTR_NAME)))
      .andExpect(jsonPath("$[0].value", is(ATTR_VALUE)));

    attr.setValue(null);

    mvc.perform(
        put("/iam/group/{id}/attributes", testGroup.getUuid()).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(attr)))
      .andExpect(status().isOk());

    mvc.perform(get("/iam/group/{id}/attributes", testGroup.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$", hasSize(1)))
      .andExpect(jsonPath("$[0].name", is(ATTR_NAME)))
      .andExpect(jsonPath("$[0].value", nullValue()));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void deleteAttributeWorks() throws Exception {
    IamGroup testGroup =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc.perform(
        put("/iam/group/{id}/attributes", testGroup.getUuid()).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(attr)))
      .andExpect(status().isOk());

    mvc.perform(delete("/iam/group/{id}/attributes", testGroup.getUuid()).param("name", ATTR_NAME))
      .andExpect(status().isNoContent());

    // A delete succeeds even if the attribute isn't there
    mvc.perform(delete("/iam/group/{id}/attributes", testGroup.getUuid()).param("name", ATTR_NAME))
      .andExpect(status().isNoContent());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void nonExistingGroupIsHandledCorrectly() throws Exception {
    String randomUuid = UUID.randomUUID().toString();
    AttributeDTO attr = new AttributeDTO();

    attr.setName(ATTR_NAME);
    attr.setValue(ATTR_VALUE);

    mvc.perform(get("/iam/group/{id}/attributes", randomUuid))
      .andExpect(NOT_FOUND)
      .andExpect(jsonPath("$.error", containsString("Group not found")));

    mvc
      .perform(put("/iam/group/{id}/attributes", randomUuid).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(attr)))
      .andExpect(NOT_FOUND)
      .andExpect(jsonPath("$.error", containsString("Group not found")));

    mvc.perform(delete("/iam/group/{id}/attributes", randomUuid).param("name", ATTR_NAME))
      .andExpect(NOT_FOUND)
      .andExpect(jsonPath("$.error", containsString("Group not found")));

  }

}
