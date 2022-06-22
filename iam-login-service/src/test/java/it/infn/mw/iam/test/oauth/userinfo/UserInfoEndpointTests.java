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
package it.infn.mw.iam.test.oauth.userinfo;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
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

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;
import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;



@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class UserInfoEndpointTests {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;


  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Before
  public void setup() throws Exception {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred", scopes = {"openid"})
  public void testUserInfoEndpointReturs404ForClientCredentialsToken() throws Exception {
    mvc.perform(get("/userinfo")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid"})
  public void testUserInfoEndpointRetursOk() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.*", Matchers.hasSize(1)))
      .andExpect(jsonPath("$.sub").exists());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"})
  public void testUserInfoEndpointRetursAllExpectedInfo() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.organisation_name", is("indigo-dc")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"}, externallyAuthenticated = true,
      externalAuthenticationType = ExternalAuthenticationType.OIDC)
  public void testUserInfoEndpointRetursExtAuthnClaim() throws Exception {

    // @formatter:off
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.external_authn").exists());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"})
  public void userinfoEndpointReturnsUpdatedAtClaimAsANumber() throws Exception {

    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.updated_at").isNumber());
  }


  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"})
  public void userinfoEndpointDoesNotReturnsSshKeysWithoutScope() throws Exception {

    IamAccount test = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    IamSshKey key = new IamSshKey();
    key.setLabel("test");
    key.setValue("test");
    key.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint("test"));

    accountService.addSshKey(test, key);
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.ssh_keys").doesNotExist());

  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
      scopes = {"openid", "profile", "ssh-keys"})
  public void userinfoEndpointDoesNotReturnsSshKeysWithAppropriateScope() throws Exception {
    IamAccount test = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    IamSshKey key = new IamSshKey();
    key.setLabel("test");
    key.setValue("test");
    key.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint("test"));

    accountService.addSshKey(test, key);
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.ssh_keys").isArray())
      .andExpect(jsonPath("$.ssh_keys", hasSize(1)))
      .andExpect(
          jsonPath("$.ssh_keys[0].fingerprint", is(RSAPublicKeyUtils.getSHA256Fingerprint("test"))))
      .andExpect(jsonPath("$.ssh_keys[0].value", is("test")));

  }

}
