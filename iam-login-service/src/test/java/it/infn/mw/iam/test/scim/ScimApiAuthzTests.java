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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ScimApiAuthzTests {

  @Autowired
  private MockMvc mvc;

  private static final String GROUP_URI = ScimUtils.getGroupsLocation();
  private static final String USER_URI = ScimUtils.getUsersLocation();

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void testAdminGroupsListRequestFailure() throws Exception {

    mvc.perform(get(GROUP_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void testAdminUsersListRequestFailure() throws Exception {

    mvc.perform(get(USER_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "gm", authorities = {"ROLE_GM:"})
  public void testGMGroupsListRequestFailure() throws Exception {

    mvc.perform(get(GROUP_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "gm", authorities = {"ROLE_GM:"})
  public void testGMUsersListRequestFailure() throws Exception {

    mvc.perform(get(USER_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  public void testAdminScimUserRequestFailure() throws Exception {

    // Some existing user as defined in the test db
    String uuid = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";

    mvc.perform(get(USER_URI + "/" + uuid).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("access_denied")))
      .andExpect(jsonPath("$.error_description", equalTo("Access is denied")));
  }

}
