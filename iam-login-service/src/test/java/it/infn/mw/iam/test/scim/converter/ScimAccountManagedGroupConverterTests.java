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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
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

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.account.group_manager.AccountGroupManagerService;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"scim.include_managed_groups=true"})
public class ScimAccountManagedGroupConverterTests {

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private AccountGroupManagerService groupManagerService;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private ScimResourceLocationProvider resourceLocationProvider;
  
  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  private IamGroup productionGroup;
  private ScimGroupRef producGroupRef;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
    productionGroup = groupRepo.findByName("Production").get();
    producGroupRef = ScimGroupRef.builder()
      .value(productionGroup.getUuid())
      .display(productionGroup.getName())
      .ref(resourceLocationProvider.groupLocation(productionGroup.getUuid()))
      .build();

  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = "admin")
  public void testManagedGroupsReturnedIfAllowedByConfigurationSerializedByDefault() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test")
        .orElseThrow(() -> new AssertionError("Expected test account not found"));

    mvc.perform(get(ScimUtils.getUserLocation(testAccount.getUuid())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.MANAGED_GROUPS).doesNotExist());

    groupManagerService.addManagedGroupForAccount(testAccount, productionGroup);

    ScimUser updatedUser = scimUtils.getUser(testAccount.getUuid());
    System.out.println(mapper.writeValueAsString(updatedUser));

    assertThat(updatedUser.getIndigoUser().getManagedGroups().size(), equalTo(1));
    assertThat(updatedUser.getIndigoUser().getManagedGroups().contains(producGroupRef), equalTo(true));
  }
}
