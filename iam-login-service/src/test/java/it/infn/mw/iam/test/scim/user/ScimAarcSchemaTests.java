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

import static org.hamcrest.CoreMatchers.hasItems;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;

@SpringBootTest(classes = {IamLoginService.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@TestPropertySource(properties = "scim.enable-aarc=true")
class ScimAarcSchemaTests {

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void testScimAarcUser() throws Exception {

    scimUtils.getUsers()
      .andExpect(jsonPath("$.Resources[0].schemas", hasItems(ScimUser.USER_SCHEMA,
          ScimConstants.INDIGO_USER_SCHEMA, ScimConstants.AARC_USER_SCHEMA)));
  }
}
