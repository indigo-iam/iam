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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read"})
public class ScimGroupProvisioningAttributeFilterTests {

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  private final static String GROUPS_URI = ScimUtils.getGroupsLocation();

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testReuturnOnlyDisplayNameRequest() throws Exception {
    //@formatter:off
    mvc.perform(get(GROUPS_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", "1")
        .param("attributes", "displayName"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(22)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))))
      .andExpect(jsonPath("$.Resources[0].id", is(Matchers.not(nullValue()))))
      .andExpect(jsonPath("$.Resources[0].schemas", is(Matchers.not(nullValue()))))
      .andExpect(jsonPath("$.Resources[0].displayName", is(Matchers.not(nullValue()))));
    //@formatter:on
  }

  @Test
  public void testMultipleAttrsRequest() throws Exception {
    //@formatter:off
    mvc.perform(get(GROUPS_URI)
        .contentType(SCIM_CONTENT_TYPE)
        .param("count", "2")
        .param("attributes", "displayName"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(22)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(ScimListResponse.SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.Resources[0].id", is(Matchers.not(nullValue()))))
      .andExpect(jsonPath("$.Resources[0].schemas", is(not(nullValue()))))
      .andExpect(jsonPath("$.Resources[0].displayName", is(not(nullValue()))));
    //@formatter:on
  }

}
