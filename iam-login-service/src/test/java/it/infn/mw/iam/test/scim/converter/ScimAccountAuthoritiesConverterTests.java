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
@TestPropertySource(properties = {"scim.include_authorities=true"})
public class ScimAccountAuthoritiesConverterTests {

  private static final String USER_AUTHORITY = "ROLE_USER";
  private static final String GM_AUTHORITY = "ROLE_GM" + UUID.randomUUID();
  private static final String ADMIN_AUTHORITY = "ROLE_ADMIN";

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
    gmAuthority.setAuthority(GM_AUTHORITY);
    authRepo.save(gmAuthority);
  }

  @After
  public void teardown() {
    authRepo.delete(gmAuthority);
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = "admin")
  public void testAuthoritiesReturnedIfAllowedByConfigurationSerializedByDefault()
      throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test_106")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    ScimUser user = scimUtils.getUser(testAccount.getUuid());

    assertThat(user.getIndigoUser().getAuthorities().size(), equalTo(1));
    assertThat(user.getIndigoUser().getAuthorities().get(0), equalTo(USER_AUTHORITY));

    authorityService.addAuthorityToAccount(testAccount, GM_AUTHORITY);

    user = scimUtils.getUser(testAccount.getUuid());

    assertThat(user.getIndigoUser().getAuthorities().size(), equalTo(2));
    assertThat(user.getIndigoUser().getAuthorities().contains(USER_AUTHORITY), equalTo(true));
    assertThat(user.getIndigoUser().getAuthorities().contains(GM_AUTHORITY), equalTo(true));

    authorityService.addAuthorityToAccount(testAccount, ADMIN_AUTHORITY);

    user = scimUtils.getUser(testAccount.getUuid());

    assertThat(user.getIndigoUser().getAuthorities().size(), equalTo(3));
    assertThat(user.getIndigoUser().getAuthorities().contains(USER_AUTHORITY), equalTo(true));
    assertThat(user.getIndigoUser().getAuthorities().contains(GM_AUTHORITY), equalTo(true));
    assertThat(user.getIndigoUser().getAuthorities().contains(ADMIN_AUTHORITY), equalTo(true));

  }
}
