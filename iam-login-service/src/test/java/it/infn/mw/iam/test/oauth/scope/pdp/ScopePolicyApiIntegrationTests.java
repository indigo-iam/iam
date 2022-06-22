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
package it.infn.mw.iam.test.oauth.scope.pdp;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scope_policy.GroupRefDTO;
import it.infn.mw.iam.api.scope_policy.IamAccountRefDTO;
import it.infn.mw.iam.api.scope_policy.ScopePolicyDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ScopePolicyApiIntegrationTests extends ScopePolicyTestUtils {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamScopePolicyRepository scopePolicyRepo;


  @Autowired
  private ScimResourceLocationProvider locationProvider;


  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;
  
  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void listPolicyRequiresFullAuthenticationTest() throws Exception {

    mvc.perform(get("/iam/scope_policies")).andExpect(status().isUnauthorized());

  }


  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void listPolicyWorksForAdminUserTest() throws Exception {
    mvc.perform(get("/iam/scope_policies"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(Matchers.hasSize(1)))
      .andExpect(jsonPath("$[0].description").exists())
      .andExpect(jsonPath("$[0].description").value("Default Permit ALL policy"));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void listUserPolicyTest() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    IamScopePolicy p = initDenyScopePolicy();
    p.setDescription("Deny all to test user");
    p.setAccount(testAccount);

    scopePolicyRepo.save(p);


    mvc.perform(get("/iam/scope_policies"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(Matchers.hasSize(2)))
      .andExpect(jsonPath("$[0].description").exists())
      .andExpect(jsonPath("$[0].description").value("Default Permit ALL policy"))
      .andExpect(jsonPath("$[0].account").doesNotExist())
      .andExpect(jsonPath("$[0].group").doesNotExist())
      .andExpect(jsonPath("$[0].scopes").doesNotExist())
      .andExpect(jsonPath("$[1].description").value("Deny all to test user"))
      .andExpect(jsonPath("$[1].account").exists())
      .andExpect(jsonPath("$[1].group").doesNotExist())
      .andExpect(jsonPath("$[1].account.username").value(equalTo(testAccount.getUsername())))
      .andExpect(jsonPath("$[1].account.uuid").value(equalTo(testAccount.getUuid())))
      .andExpect(jsonPath("$[1].account.location")
        .value(equalTo(locationProvider.userLocation(testAccount.getUuid()))))
      .andExpect(jsonPath("$[1].scopes").doesNotExist());

  }


  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void listGroupPolicyTest() throws Exception {

    IamGroup prodGroup = groupRepo.findByName("Production")
      .orElseThrow(() -> new AssertionError("Expected production group not found"));

    IamScopePolicy p = initDenyScopePolicy();
    p.setDescription("Deny all to Production group members");
    p.setGroup(prodGroup);

    scopePolicyRepo.save(p);


    mvc.perform(get("/iam/scope_policies"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(Matchers.hasSize(2)))
      .andExpect(jsonPath("$[0].description").exists())
      .andExpect(jsonPath("$[0].description").value("Default Permit ALL policy"))
      .andExpect(jsonPath("$[0].account").doesNotExist())
      .andExpect(jsonPath("$[0].group").doesNotExist())
      .andExpect(jsonPath("$[0].scopes").doesNotExist())
      .andExpect(jsonPath("$[1].description").value("Deny all to Production group members"))
      .andExpect(jsonPath("$[1].account").doesNotExist())
      .andExpect(jsonPath("$[1].group").exists())
      .andExpect(jsonPath("$[1].group.name").value(equalTo(prodGroup.getName())))
      .andExpect(jsonPath("$[1].group.uuid").value(equalTo(prodGroup.getUuid())))
      .andExpect(jsonPath("$[1].group.location")
        .value(equalTo(locationProvider.groupLocation(prodGroup.getUuid()))))
      .andExpect(jsonPath("$[1].scopes").doesNotExist());

  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void defaultPolicyRuleValidationTest() throws Exception {
    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule("ciccio");

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(startsWith("Invalid scope policy")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void invalidAccountIdRuleValidationTest() throws Exception {
    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    IamAccountRefDTO accountRef = new IamAccountRefDTO();
    accountRef.setUuid(UUID.randomUUID().toString());
    sp.setAccount(accountRef);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error")
        .value(Matchers.equalTo("Invalid scope policy: no IAM account found for the given UUID")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void invalidGroupIdRuleValidationTest() throws Exception {
    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());

    GroupRefDTO groupRef = new GroupRefDTO();

    groupRef.setUuid(UUID.randomUUID().toString());

    sp.setGroup(groupRef);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error")
        .value(Matchers.equalTo("no group found for the given UUID")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void invalidScopePolicyRuleValidationTest() throws Exception {
    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    IamGroup analysisGroup = groupRepo.findByName("Analysis")
      .orElseThrow(() -> new AssertionError("Expected Analysis group not found"));

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());

    GroupRefDTO groupRef = new GroupRefDTO();
    groupRef.setUuid(analysisGroup.getUuid());
    sp.setGroup(groupRef);

    IamAccountRefDTO accountRef = new IamAccountRefDTO();
    accountRef.setUuid(testAccount.getUuid());
    sp.setAccount(accountRef);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(
          Matchers.equalTo("Invalid scope policy: group and account cannot be both non-null")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void invalidScopePolicyScopesLengthLowerBound() throws Exception {

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet(""));
    String serializedSp = mapper.writeValueAsString(sp);

    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(Matchers
        .equalTo("Invalid scope policy: scope length must be >= 1 and < 255 characters")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void invalidScopePolicyRepresentationTest() throws Exception {
    final String INVALID_POLICY = new String(
        Files.readAllBytes(Paths.get("src/test/resources/api/scope_policy/invalid_policy.json")));

    mvc.perform(post("/iam/scope_policies").content(INVALID_POLICY).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(Matchers
        .equalTo("Invalid scope policy: could not parse the policy JSON representation")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void invalidScopePolicyScopesLengthUpperBound() throws Exception {

    StringBuilder s = new StringBuilder();
    for (int i = 0; i < 256; i++)
      s.append('s');

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet(s.toString()));
    String serializedSp = mapper.writeValueAsString(sp);

    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(Matchers
        .equalTo("Invalid scope policy: scope length must be >= 1 and < 255 characters")));
  }
  
  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void invalidScopeMatchingPolicy() throws Exception {

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setMatchingPolicy("PATH");

    String serializedSp = mapper.writeValueAsString(sp);

    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(Matchers
        .equalTo("Invalid scope policy: custom matching policy requires one or more scopes")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testDefaultPolicyCreation() throws Exception {

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet("scim:read", "scim:write"));

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    assertThat(scopePolicyRepo.count(), equalTo(2L));
  }
  
  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testMatchingPolicyIsRequired() throws Exception {

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setMatchingPolicy(null);
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet("scim:read", "scim:write"));

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is("Invalid scope policy: matching policy cannot be empty or null")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testDefaultPolicyCreationNoScopes() throws Exception {

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    assertThat(scopePolicyRepo.count(), equalTo(2L));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testAccountPolicyCreation() throws Exception {

    // Cleanup all policies
    scopePolicyRepo.deleteAll();

    assertThat(scopePolicyRepo.count(), equalTo(0L));

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet("scim:read", "scim:write"));

    IamAccountRefDTO account = new IamAccountRefDTO();
    account.setUuid(testAccount.getUuid());
    sp.setAccount(account);

    String serializedSp = mapper.writeValueAsString(sp);
    System.out.println(serializedSp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    mvc.perform(get("/iam/scope_policies"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(Matchers.hasSize(1)))
      .andExpect(jsonPath("$[0].description").doesNotExist())
      .andExpect(jsonPath("$[0].account").exists())
      .andExpect(jsonPath("$[0].group").doesNotExist())
      .andExpect(jsonPath("$[0].scopes").exists())
      .andExpect(jsonPath("$[0].scopes").value(Matchers.hasItems("scim:read", "scim:write")))
      .andExpect(jsonPath("$[0].account.username").value(equalTo(testAccount.getUsername())))
      .andExpect(jsonPath("$[0].account.uuid").value(equalTo(testAccount.getUuid())))
      .andExpect(jsonPath("$[0].account.location")
        .value(equalTo(locationProvider.userLocation(testAccount.getUuid()))));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testGroupPolicyCreation() throws Exception {
    // Cleanup all policies
    scopePolicyRepo.deleteAll();

    assertThat(scopePolicyRepo.count(), equalTo(0L));

    IamGroup analysisGroup = groupRepo.findByName("Analysis")
      .orElseThrow(() -> new AssertionError("Expected Analysis group not found"));

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet("scim:read", "scim:write"));

    GroupRefDTO groupRef = new GroupRefDTO();
    groupRef.setUuid(analysisGroup.getUuid());
    sp.setGroup(groupRef);

    String serializedSp = mapper.writeValueAsString(sp);
    
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    mvc.perform(get("/iam/scope_policies"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(Matchers.hasSize(1)))
      .andExpect(jsonPath("$[0].description").doesNotExist())
      .andExpect(jsonPath("$[0].account").doesNotExist())
      .andExpect(jsonPath("$[0].group").exists())
      .andExpect(jsonPath("$[0].group.name").value(equalTo(analysisGroup.getName())))
      .andExpect(jsonPath("$[0].group.uuid").value(equalTo(analysisGroup.getUuid())))
      .andExpect(jsonPath("$[0].group.location")
        .value(equalTo(locationProvider.groupLocation(analysisGroup.getUuid()))))
      .andExpect(jsonPath("$[0].scopes").value(Matchers.hasItems("scim:read", "scim:write")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testScopePolicyDeletion() throws Exception {
    mvc.perform(MockMvcRequestBuilders.delete("/iam/scope_policies/1"))
      .andExpect(status().isNoContent());

    mvc.perform(get("/iam/scope_policies"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").value(Matchers.hasSize(0)));

    mvc.perform(MockMvcRequestBuilders.delete("/iam/scope_policies/1"))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error").exists())
      .andExpect(jsonPath("$.error").value("No scope policy found for id: 1"));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testScopePolicyAccess() throws Exception {

    mvc.perform(get("/iam/scope_policies/1"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.description").exists())
      .andExpect(jsonPath("$.description").value("Default Permit ALL policy"));

    scopePolicyRepo.deleteAll();

    mvc.perform(get("/iam/scope_policies/1"))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error").exists())
      .andExpect(jsonPath("$.error").value("No scope policy found for id: 1"));

  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testScopeCascade() throws Exception {

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet("scim:read", "scim:write"));

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.PERMIT.name());
    sp.setScopes(Sets.newHashSet("scim:read", "scim:write"));

    serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    assertThat(scopePolicyRepo.count(), equalTo(3L));
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"})
  public void testDefaultPolicyUpdateFailsWithForbiddenForUnauthorizedUser() throws Exception {
    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setId(1L);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(put("/iam/scope_policies/1").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isForbidden());
  }

  @Test
  public void testDefaultPolicyUpdateFailsWithAnonymousUser() throws Exception {
    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setRule(PolicyRule.DENY.name());
    sp.setId(1L);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(put("/iam/scope_policies/1").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testDefaultPolicyUpdate() throws Exception {
    final String description = "DENY ALL!";

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setDescription(description);
    sp.setRule(PolicyRule.DENY.name());
    sp.setId(1L);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(put("/iam/scope_policies/1").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isNoContent());

    mvc.perform(get("/iam/scope_policies/1"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(1)))
      .andExpect(jsonPath("$.rule", equalTo("DENY")))
      .andExpect(jsonPath("$.description", equalTo(description)))
      .andExpect(jsonPath("$.scopes").doesNotExist());

  }
  
  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testPolicyUpdateValidationError() throws Exception {
    final String description = "DENY ALL!";

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setDescription(description);
    // NO rule set
    sp.setId(1L);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(put("/iam/scope_policies/1").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("Invalid scope policy: rule cannot be empty"));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testNonExistingPolicyUpdate() throws Exception {
    final String description = "DENY ALL!";

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setDescription(description);
    sp.setRule(PolicyRule.DENY.name());
    sp.setId(10L);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(put("/iam/scope_policies/10").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error").value("No scope policy found for id: 10"));

  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testEquivalentPolicyCreationNotAllowed() throws Exception {
    IamGroup analysisGroup = groupRepo.findByName("Analysis")
      .orElseThrow(() -> new AssertionError("Expected Analysis group not found"));

    final String description = "DENY ALL!";

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setDescription(description);
    sp.setRule(PolicyRule.DENY.name());

    GroupRefDTO groupRef = new GroupRefDTO();
    groupRef.setUuid(analysisGroup.getUuid());
    sp.setGroup(groupRef);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());

    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", startsWith("Duplicate policy error")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
  public void testEquivalentPolicyUpdateNotAllowed() throws Exception {
    IamGroup analysisGroup = groupRepo.findByName("Analysis")
      .orElseThrow(() -> new AssertionError("Expected Analysis group not found"));

    ScopePolicyDTO sp = new ScopePolicyDTO();
    sp.setDescription("sp");
    sp.setRule(PolicyRule.DENY.name());
    sp.setScopes(Sets.newHashSet(SCIM_READ, SCIM_WRITE));

    GroupRefDTO groupRef = new GroupRefDTO();
    groupRef.setUuid(analysisGroup.getUuid());
    sp.setGroup(groupRef);

    String serializedSp = mapper.writeValueAsString(sp);
    mvc.perform(post("/iam/scope_policies").content(serializedSp).contentType(APPLICATION_JSON))
      .andExpect(status().isCreated());


    ScopePolicyDTO sp2 = new ScopePolicyDTO();
    sp2.setDescription("sp2");
    sp2.setRule(PolicyRule.DENY.name());
    sp2.setGroup(groupRef);

    mvc.perform(post("/iam/scope_policies").content(mapper.writeValueAsString(sp2))
      .contentType(APPLICATION_JSON)).andExpect(status().isCreated());
    
    // Resolve sp2 policy id
    String result = mvc.perform(get("/iam/scope_policies"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    List<ScopePolicyDTO> policies =
        mapper.readValue(result, new TypeReference<List<ScopePolicyDTO>>() {});

    ScopePolicyDTO savedObject =
        policies.stream().filter(p -> p.getDescription().equals("sp2")).findAny().orElseThrow(
            () -> new AssertionError("Expected scope policy not found"));

    sp2.setScopes(Sets.newHashSet(SCIM_READ));
    
    mvc
      .perform(put("/iam/scope_policies/{id}", savedObject.getId())
        .content(mapper.writeValueAsString(sp2)).contentType(APPLICATION_JSON))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", startsWith("Duplicate policy error")));

  }

}
