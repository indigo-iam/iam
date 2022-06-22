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
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(
    properties = {"scim.include_labels[0].name=test", "scim.include_labels[0].prefix=iam"})
public class ScimAccountLabelConverterTests {

  private static final String IAM = "iam";
  private static final String TEST = "test";
  private static final String TOAST = "test";
  private static final String VAL = "val";

  private static final IamLabel IAM_TEST_LABEL =
      IamLabel.builder().prefix(IAM).name(TEST).value(VAL).build();

  private static final IamLabel IAM_TOAST_LABEL =
      IamLabel.builder().prefix(IAM).name(TOAST).value(VAL).build();

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
  public void testLabelsReturnedIfAllowedByConfigurationSerializedByDefault() throws Exception {
    
    IamAccount testAccount = accountRepo.findByUsername(TEST)
        .orElseThrow(() -> new AssertionError("Expected test account not found"));
  
    mvc.perform(get(ScimUtils.getUserLocation(testAccount.getUuid())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS).doesNotExist());

    accountService.setLabel(testAccount, IAM_TEST_LABEL);

    mvc.perform(get(ScimUtils.getUserLocation(testAccount.getUuid())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS).exists())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS).isArray())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS, hasSize(1)))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS+"[0].name").value(TEST))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS+"[0].prefix").value(IAM))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS + "[0].prefix").value(IAM));

    accountService.setLabel(testAccount, IAM_TOAST_LABEL);

    mvc.perform(get(ScimUtils.getUserLocation(testAccount.getUuid())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS).exists())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS).isArray())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS, hasSize(1)))
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS + "[0].name").value(TEST))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS + "[0].prefix").value(IAM))
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS + "[0].prefix").value(IAM));

  }
}
