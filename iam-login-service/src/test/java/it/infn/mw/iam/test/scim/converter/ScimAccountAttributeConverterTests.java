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
package it.infn.mw.iam.test.scim.converter;

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
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"scim.include_attributes[0].name=test0"})
public class ScimAccountAttributeConverterTests {

  private static final String TEST0 = "test0";
  private static final String VAL0 = "val0";
  private static final String TEST1 = "test1";
  private static final String VAL1 = "val1";

  private static final IamAttribute IAM_TEST0_ATTRIBUTE = IamAttribute.newInstance(TEST0, VAL0);
  private static final IamAttribute IAM_TEST1_ATTRIBUTE = IamAttribute.newInstance(TEST1, VAL1);

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountService accountService;

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
  @WithMockUser(roles = {"ADMIN", "USER"}, username = "admin")
  public void testAttributesReturnedIfAllowedByConfigurationSerializedByDefault() throws Exception {
    
    IamAccount testAccount = accountRepo.findByUsername("test")
        .orElseThrow(() -> new AssertionError("Expected test account not found"));
  
    mvc.perform(get(ScimUtils.getUserLocation(testAccount.getUuid())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS).doesNotExist());

    accountService.setAttribute(testAccount, IAM_TEST0_ATTRIBUTE);

    mvc.perform(get(ScimUtils.getUserLocation(testAccount.getUuid())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES).exists())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES).isArray())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES, hasSize(1)))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES + "[0].name").value(TEST0))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES + "[0].value").value(VAL0));

    accountService.setAttribute(testAccount, IAM_TEST1_ATTRIBUTE);

    mvc.perform(get(ScimUtils.getUserLocation(testAccount.getUuid())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES).exists())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES).isArray())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES, hasSize(1)))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES + "[0].name").value(TEST0))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES + "[0].value").value(VAL0));

  }
}
