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


import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.PATH;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Iterator;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyPDP;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class ScopePolicyPdpTests extends ScopePolicyTestUtils {

  @Autowired
  IamScopePolicyRepository policyScopeRepo;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  ScopePolicyPDP pdp;


  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  @Test
  public void testBasicDefaultPolicyDecision() {

    IamAccount testAccount = findTestAccount();
    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet("openid", "profile", "scim:read"), testAccount);

    assertThat(filteredScopes, hasSize(3));
    assertThat(filteredScopes, hasItems("openid", "profile", "scim:read"));

  }

  @Test
  public void testAccountPolicyIsEnforced() {
    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.linkAccount(testAccount);
    up.getScopes().add(SCIM_WRITE);

    policyScopeRepo.save(up);

    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet("openid", "profile", "scim:write"), testAccount);
    assertThat(filteredScopes, hasSize(2));
    assertThat(filteredScopes, hasItems("openid", "profile"));
  }

  @Test
  public void testAccountPolicyIsCompletelyEnforced() {
    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();
    up.linkAccount(testAccount);
    up.getScopes().add(SCIM_WRITE);
    up.getScopes().add(OPENID);
    up.getScopes().add(PROFILE);

    policyScopeRepo.save(up);

    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet(OPENID, PROFILE, SCIM_WRITE), testAccount);
    assertThat(filteredScopes, hasSize(0));

  }

  @Test
  public void testGroupPolicyIsEnforced() {
    IamAccount testAccount = findTestAccount();

    Iterator<IamAccountGroupMembership> groupsIter = testAccount.getGroups().iterator();

    IamGroup firstGroup = groupsIter.next().getGroup();


    IamScopePolicy up = initDenyScopePolicy();
    up.getScopes().add(SCIM_WRITE);
    up.linkGroup(firstGroup);

    policyScopeRepo.save(up);

    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet("openid", "profile", "scim:write"), testAccount);
    assertThat(filteredScopes, hasSize(2));
    assertThat(filteredScopes, hasItems("openid", "profile"));
  }

  
  @Test
  public void testChainedOverrideAtGroupIsEnforced() {
    IamAccount testAccount = findTestAccount();

    Iterator<IamAccountGroupMembership> groupsIter = testAccount.getGroups().iterator();

    IamGroup firstGroup = groupsIter.next().getGroup();

    IamScopePolicy gp = initPermitScopePolicy();
    gp.linkGroup(firstGroup);
    gp.setScopes(Sets.newHashSet(OPENID, PROFILE));
    
    
    policyScopeRepo.save(gp);
    
    Set<String> filteredScopes = pdp
        .filterScopes(Sets.newHashSet("openid", "profile"), testAccount);
    
    assertThat(filteredScopes, hasSize(2));
    assertThat(filteredScopes, hasItems("openid", "profile"));
  }
  
  
  @Test
  public void testChainedOverrideIsEnforced() {
    IamAccount testAccount = findTestAccount();

    Iterator<IamAccountGroupMembership> groupsIter = testAccount.getGroups().iterator();

    IamGroup firstGroup = groupsIter.next().getGroup();

    IamScopePolicy gp = initPermitScopePolicy();
    gp.linkGroup(firstGroup);
    gp.setScopes(Sets.newHashSet(OPENID, PROFILE));

    policyScopeRepo.save(gp);

    IamScopePolicy ap = initPermitScopePolicy();
    ap.linkAccount(testAccount);
    ap.getScopes().add(SCIM_WRITE);

    policyScopeRepo.save(ap);

    Set<String> filteredScopes = pdp
      .filterScopes(Sets.newHashSet("openid", "profile", "scim:write", "scim:read"), testAccount);

    assertThat(filteredScopes, hasSize(4));
    assertThat(filteredScopes, hasItems("openid", "profile", "scim:write", "scim:read"));
  }

  @Test
  public void testConflictingGroupPolicyDenyOverrides() {
    IamAccount testAccount = findTestAccount();

    Iterator<IamAccountGroupMembership> groupsIter = testAccount.getGroups().iterator();


    IamGroup firstGroup = groupsIter.next().getGroup();
    IamGroup secondGroup = groupsIter.next().getGroup();

    IamScopePolicy up = initDenyScopePolicy();
    up.getScopes().add(SCIM_WRITE);
    up.linkGroup(firstGroup);
    up.setDescription(firstGroup.getName());
    policyScopeRepo.save(up);

    up = initPermitScopePolicy();
    up.getScopes().add(SCIM_WRITE);
    up.linkGroup(secondGroup);
    up.setDescription(secondGroup.getName());
    policyScopeRepo.save(up);

    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet("openid", "profile", "scim:write"), testAccount);
    assertThat(filteredScopes, hasSize(2));
    assertThat(filteredScopes, hasItems("openid", "profile"));
  }

  @Test
  public void testConflictingGroupPolicyDenyOverrides2() {
    IamAccount testAccount = findTestAccount();

    Iterator<IamAccountGroupMembership> groupsIter = testAccount.getGroups().iterator();


    IamGroup firstGroup = groupsIter.next().getGroup();
    IamGroup secondGroup = groupsIter.next().getGroup();

    IamScopePolicy up = initPermitScopePolicy();
    up.getScopes().add(SCIM_WRITE);
    up.linkGroup(firstGroup);
    up.setDescription(firstGroup.getName());
    policyScopeRepo.save(up);

    up = initDenyScopePolicy();
    up.getScopes().add(SCIM_WRITE);
    up.linkGroup(secondGroup);
    up.setDescription(secondGroup.getName());
    policyScopeRepo.save(up);

    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet("openid", "profile", "scim:write"), testAccount);
    assertThat(filteredScopes, hasSize(2));
    assertThat(filteredScopes, hasItems("openid", "profile"));
  }
  
  
  @Test
  public void testPathFiltering() {
    
    IamAccount testAccount = findTestAccount();
    IamScopePolicy up = initDenyScopePolicy();
    
    up.getScopes().add("read:/");
    up.getScopes().add("write:/");
    up.setMatchingPolicy(PATH);
    
    policyScopeRepo.save(up);

    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet("openid", "profile", "read:/", "write", "read:/sub/path"), testAccount);

    assertThat(filteredScopes, hasSize(3));
    assertThat(filteredScopes, hasItems("openid", "profile", "write"));
  }
  
  @Test
  public void testPathPermit() {
    
    IamAccount testAccount = findTestAccount();
    IamScopePolicy up = initPermitScopePolicy();
    
    up.getScopes().add("read:/");
    up.getScopes().add("write:/");
    up.setMatchingPolicy(PATH);
    
    policyScopeRepo.save(up);

    Set<String> filteredScopes =
        pdp.filterScopes(Sets.newHashSet("openid", "profile", "read:/", "write", "read:/sub/path"), testAccount);

    assertThat(filteredScopes, hasSize(5));
    assertThat(filteredScopes, hasItems("openid", "profile", "write", "read:/", "read:/sub/path"));
  }

}
