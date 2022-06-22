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
package it.infn.mw.iam.test.scim.user;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimListResponse.SCHEMA;
import static it.infn.mw.iam.test.TestUtils.TOTAL_USERS_COUNT;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.scim.ScimUtils.ParamsBuilder;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE})
public class ScimUserProvisioningAttributeFilterTests {

  @Autowired
  private ScimRestUtilsMvc scimUtils;
  
  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;
  
  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testReuturnOnlyUsernameRequest() throws Exception {

    scimUtils.getUsers(ParamsBuilder.builder().count(1).attributes("userName").build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(1))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].emails").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].displayName").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].nickName").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].profileUrl").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].locale").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].timezone").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].active").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].title").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].addresses").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].certificates").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].groups").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser").doesNotExist());

  }

  @Test
  public void testMultipleAttrsRequest() throws Exception {

    scimUtils
      .getUsers(ParamsBuilder.builder()
        .count(2)
        .attributes("userName,emails," + INDIGO_USER_SCHEMA)
        .build())
      .andExpect(jsonPath("$.totalResults", equalTo(TOTAL_USERS_COUNT)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.schemas", contains(SCHEMA)))
      .andExpect(jsonPath("$.Resources", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].schemas").exists())
      .andExpect(jsonPath("$.Resources[0].userName").exists())
      .andExpect(jsonPath("$.Resources[0].emails").exists())
      .andExpect(jsonPath("$.Resources[0].displayName").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].nickName").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].profileUrl").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].locale").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].timezone").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].active").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].title").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].addresses").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].certificates").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].groups").doesNotExist())
      .andExpect(jsonPath("$.Resources[0].urn:indigo-dc:scim:schemas:IndigoUser").exists());

  }

}
