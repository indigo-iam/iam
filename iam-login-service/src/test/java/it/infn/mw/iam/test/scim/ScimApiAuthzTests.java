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
package it.infn.mw.iam.test.scim;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class ScimApiAuthzTests {

  private static final String PRODUCTION_GROUP_ID = "c617d586-54e6-411d-8e38-64967798fa8a";
  private static final String TEST_001_GROUP_ID = "c617d586-54e6-411d-8e38-649677980001";
  private static final String TEST_USER_ID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";

  private static final String GROUP_URI = ScimUtils.getGroupsLocation();
  private static final String USER_URI = ScimUtils.getUsersLocation();

  @Autowired
  private MockMvc mvc;

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  void testAdminGroupsListRequestFailure() throws Exception {

    mvc.perform(get(GROUP_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  void testAdminUsersListRequestFailure() throws Exception {

    mvc.perform(get(USER_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "gm", authorities = {"ROLE_GM:"})
  void testGMGroupsListRequestFailure() throws Exception {

    mvc.perform(get(GROUP_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "gm", authorities = {"ROLE_GM:"})
  void testGMUsersListRequestFailure() throws Exception {

    mvc.perform(get(USER_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  void testAdminScimUserRequestFailure() throws Exception {

    mvc.perform(get(USER_URI + "/" + TEST_USER_ID).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @ParameterizedTest
  @ValueSource(strings = {PRODUCTION_GROUP_ID, TEST_001_GROUP_ID})
  @WithMockOAuthUser(user = "gm")
  void testGroupManagerCannotAccessUserWithoutScimReadScope(String groupId) throws Exception {

    mvc.perform(get(USER_URI + "/" + TEST_USER_ID).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")));
  }

  @Test
  @WithMockUser(username = "gm", roles = {"GM:" + PRODUCTION_GROUP_ID})
  void testGroupManagerCanAccessUserInManagedGroup() throws Exception {

    mvc.perform(get(USER_URI + "/" + TEST_USER_ID).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "gm", roles = {"GM:" + TEST_001_GROUP_ID})
  void testGroupManagerCannotAccessUserInUnmanagedGroup() throws Exception {

    mvc.perform(get(USER_URI + "/" + TEST_USER_ID).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")));
  }
}
