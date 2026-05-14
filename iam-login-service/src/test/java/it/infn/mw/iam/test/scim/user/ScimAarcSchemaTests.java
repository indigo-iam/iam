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

import static org.hamcrest.CoreMatchers.equalTo;
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
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;

@SpringBootTest(classes = {IamLoginService.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@TestPropertySource(properties = "scim.enable-aarc=true")
class ScimAarcSchemaTests {

  private static final String ACCOUNT_UUID = "73f16d93-2441-4a50-88ff-85360d78c6b5";
  public static final String REFEDS_ASSURANCE_URI = "https://refeds.org/assurance";
  public static final String REFEDS_ASSURANCE_IAP_LOW_URI = "https://refeds.org/assurance/IAP/low";

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private IamAccountRepository accountRepo;

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void testScimAarcUserSchema() throws Exception {

    IamAccount account = accountRepo.findByUuid(ACCOUNT_UUID).orElseThrow();

    scimUtils.getUsers()
      .andExpect(jsonPath("$.Resources[0].schemas",
          hasItems(ScimUser.USER_SCHEMA, ScimConstants.INDIGO_USER_SCHEMA,
              ScimConstants.AARC_USER_SCHEMA)))
      .andExpect(jsonPath("$.Resources[0]['" + ScimConstants.AARC_USER_SCHEMA + "'].voPersonId",
          equalTo(ACCOUNT_UUID + "@indigo-dc")))
      .andExpect(
          jsonPath("$.Resources[0]['" + ScimConstants.AARC_USER_SCHEMA + "'].name.displayName",
              equalTo(account.getUserInfo().getName())))
      .andExpect(
          jsonPath("$.Resources[0]['" + ScimConstants.AARC_USER_SCHEMA + "'].name.familyName",
              equalTo(account.getUserInfo().getFamilyName())))
      .andExpect(jsonPath("$.Resources[0]['" + ScimConstants.AARC_USER_SCHEMA + "'].name.givenName",
          equalTo(account.getUserInfo().getGivenName())))
      .andExpect(jsonPath("$.Resources[0]['" + ScimConstants.AARC_USER_SCHEMA + "'].email",
          equalTo(account.getUserInfo().getEmail())))
      .andExpect(jsonPath("$.Resources[0]['" + ScimConstants.AARC_USER_SCHEMA
          + "'].voPersonExternalAffiliations[*].value", hasItems("member@indigo-dc")))
      .andExpect(
          jsonPath("$.Resources[0]['" + ScimConstants.AARC_USER_SCHEMA + "'].assurance[*].value",
              hasItems(REFEDS_ASSURANCE_URI, REFEDS_ASSURANCE_IAP_LOW_URI)));
  }
}
