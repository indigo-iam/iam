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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.userinfo.UserInfoResponse;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;
import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class UserInfoEndpointTests {

  @Autowired
  MockMvc mvc;

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  IamAccountService accountService;

  @Autowired
  IamAccountRepository accountRepo;

  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  void testUserInfoResponseCreationWithoutSub() {

    Map<String, Object> claims = Map.of("iss", "https://iam-example.org/");
    assertThrows(IllegalArgumentException.class, () -> {
      new UserInfoResponse(claims);
    });
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred", scopes = {"openid"}, authorities = {"ROLE_CLIENT"})
  void testUserInfoEndpointReturs404ForClientCredentialsToken() throws Exception {

    mvc.perform(get("/userinfo")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
    scopes = {"openid"})
  void testUserInfoEndpointRetursOk() throws Exception {

    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.*", Matchers.hasSize(2)))
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", Matchers.hasSize(1)))
      .andExpect(jsonPath("$.scope", containsInAnyOrder("openid")));

  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
    scopes = {"openid", "profile"})
  void testUserInfoEndpointRetursAllExpectedInfo() throws Exception {

    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", Matchers.hasSize(2)))
      .andExpect(jsonPath("$.scope", containsInAnyOrder("openid", "profile")))
      .andExpect(jsonPath("$." + IamExtraClaimNames.ORGANISATION_NAME, is("indigo-dc")))
      .andExpect(jsonPath("$." + IamExtraClaimNames.AFFILIATION, is("indigo")))
      .andReturn();
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
    scopes = {"openid", "profile"}, externallyAuthenticated = true,
    externalAuthenticationType = ExternalAuthenticationType.OIDC)
  void testUserInfoEndpointRetursExtAuthnClaim() throws Exception {

    MvcResult result = mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", Matchers.hasSize(2)))
      .andExpect(jsonPath("$.scope", containsInAnyOrder("openid", "profile")))
      .andExpect(jsonPath("$.external_authn").exists())
      .andExpect(jsonPath("$.external_authn.type", equalTo("oidc")))
      .andReturn();

    checkNoRootKeyDuplicates(result.getResponse().getContentAsString());
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
    scopes = {"openid", "profile"})
  void userinfoEndpointDoesNotReturnsSshKeysWithoutScope() throws Exception {

    IamAccount test = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    IamSshKey key = new IamSshKey();
    key.setLabel("test");
    key.setValue("test");
    key.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint("test"));

    accountService.addSshKey(test, key);
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", Matchers.hasSize(2)))
      .andExpect(jsonPath("$.scope", containsInAnyOrder("openid", "profile")))
      .andExpect(jsonPath("$.ssh_keys").doesNotExist());

  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
    scopes = {"openid", "profile", "ssh-keys"})
  void userinfoEndpointDoesNotReturnsSshKeysWithAppropriateScope() throws Exception {
    IamAccount test = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    IamSshKey key = new IamSshKey();
    key.setLabel("test");
    key.setValue("test");
    key.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint("test"));

    accountService.addSshKey(test, key);
    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", Matchers.hasSize(3)))
      .andExpect(jsonPath("$.scope", containsInAnyOrder("openid", "profile", "ssh-keys")))
      .andExpect(jsonPath("$.ssh_keys").isArray())
      .andExpect(jsonPath("$.ssh_keys", Matchers.hasSize(1)))
      .andExpect(
          jsonPath("$.ssh_keys[0].fingerprint", is(RSAPublicKeyUtils.getSHA256Fingerprint("test"))))
      .andExpect(jsonPath("$.ssh_keys[0].value", is("test")));
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", authorities = {"ROLE_USER"},
    scopes = {"openid", "profile"})
  @Transactional
  void testUserInfoEndpointReturnsNoEmptyClaims() throws Exception {

    IamAccount test = accountRepo.findByUsername("test")
        .orElseThrow(() -> new AssertionError("Expected account not found"));
    test.getUserInfo().setPicture("  ");
    accountRepo.save(test);

    mvc.perform(get("/userinfo"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.sub").exists())
      .andExpect(jsonPath("$.picture").doesNotExist())
      .andExpect(jsonPath("$.scope").exists())
      .andExpect(jsonPath("$.scope", Matchers.hasSize(2)))
      .andExpect(jsonPath("$.scope", containsInAnyOrder("openid", "profile")))
      .andExpect(jsonPath("$." + IamExtraClaimNames.ORGANISATION_NAME, is("indigo-dc")))
      .andExpect(jsonPath("$." + IamExtraClaimNames.AFFILIATION, is("indigo")));
  }


  private void checkNoRootKeyDuplicates(String content) throws IOException {

    JsonParser parser = (new JsonFactory()).createParser(content);

    Set<String> rootKeys = new HashSet<>();
    parser.nextToken();

    while (parser.nextToken() != JsonToken.END_OBJECT) {
      String fieldName = parser.getCurrentName();
      parser.nextToken();
      if (!rootKeys.add(fieldName)) {
        fail("Duplicate root key detected: " + fieldName);
      }
      parser.skipChildren();
    }
    parser.close();
  }
}
