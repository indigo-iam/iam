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

import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.api.account.authority.AccountAuthorityService;
import it.infn.mw.iam.api.scim.model.ScimAuthority;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ScimAccountAuthoritiesConverterTests {

  private static final ScimAuthority SCIM_ROLE_USER_AUTHORITY =
      ScimAuthority.builder().withAuthority("ROLE_USER").build();
  private static final ScimAuthority SCIM_ROLE_ADMIN_AUTHORITY =
      ScimAuthority.builder().withAuthority("ROLE_ADMIN").build();
  private static final ScimAuthority SCIM_ROLE_GM_AUTHORITY =
      ScimAuthority.builder().withAuthority("ROLE_GM" + UUID.randomUUID()).build();

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private AccountAuthorityService authorityService;

  @Autowired
  private IamAuthoritiesRepository authRepo;

  private IamAuthority gmAuthority;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
    gmAuthority = new IamAuthority();
    gmAuthority.setAuthority(SCIM_ROLE_GM_AUTHORITY.getAuthority());
    authRepo.save(gmAuthority);
  }

  @After
  public void teardown() {
    authRepo.delete(gmAuthority);
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = "admin")
  public void testAuthoritiesReturnedIfAllowedByConfigurationSerializedByDefault() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test_106")
        .orElseThrow(() -> new AssertionError("Expected test account not found"));

    ScimUser user = scimUtils.getUser(testAccount.getUuid());

    assertThat(user.getIndigoUser().isAdmin(), equalTo(false));

    authorityService.addAuthorityToAccount(testAccount, SCIM_ROLE_ADMIN_AUTHORITY.getAuthority());

    user = scimUtils.getUser(testAccount.getUuid());

    assertThat(user.getIndigoUser().isAdmin(), equalTo(true));
  }
}
