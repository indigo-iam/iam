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
package it.infn.mw.iam.test.scim.me;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringJUnit4ClassRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"scim.include_attributes[0].name=affiliation",
    "scim.include_authorities=true", "scim.include_managed_groups=true"})
public class ScimMeFullResponseEndpointTests {

  private final static String ME_ENDPOINT = "/scim/Me";

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() throws Exception {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockUser(username = "manager", roles = {"USER", "GM:c617d586-54e6-411d-8e38-64967798fa8a"})
  public void meEndpointFullUserInfo() throws Exception {
    //@formatter:off
    mvc.perform(get(ME_ENDPOINT)
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES).exists())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES).isArray())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES, hasSize(1)))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES + "[0].name").value("affiliation"))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES + "[0].value").value("INFN-CNAF"))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUTHORITIES).exists())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUTHORITIES).isArray())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUTHORITIES, hasSize(2)))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUTHORITIES + "[*].authority", containsInAnyOrder("ROLE_USER", "ROLE_GM:c617d586-54e6-411d-8e38-64967798fa8a")))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.MANAGED_GROUPS).exists())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.MANAGED_GROUPS).isArray())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.MANAGED_GROUPS, hasSize(1)))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.MANAGED_GROUPS + "[0].display").value("Production"))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.MANAGED_GROUPS + "[0].value").value("c617d586-54e6-411d-8e38-64967798fa8a"));
    //@formatter:on
  }

}
