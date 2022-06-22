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
package it.infn.mw.iam.test.repository;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;


@RunWith(SpringRunner.class)
@IamNoMvcTest
public class IamScopePolicyRepositoryTests extends ScopePolicyTestUtils {

  @Autowired
  private IamScopePolicyRepository policyRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamGroupService groupService;

  @Before
  public void cleanupPolicies() {
    policyRepo.deleteAll();
  }
  
  @Test
  public void testGroupPolicyCreationWorks() {

    IamGroup analysisGroup = groupRepo.findByName("Analysis")
      .orElseThrow(() -> new AssertionError("Expected Analysis group not found"));

    IamScopePolicy policy = initDenyScopePolicy();
    policy.setGroup(analysisGroup);
    policy.setRule(PolicyRule.PERMIT);
    policy.setScopes(Sets.newHashSet(SCIM_WRITE));

    policyRepo.save(policy);

    List<IamScopePolicy> policies = policyRepo.findByGroup(analysisGroup);

    assertThat(policies, hasSize(1));
    assertThat(policies.get(0).getGroup(), equalTo(analysisGroup));
    assertThat(policies.get(0).getAccount(), nullValue());
    assertThat(policies.get(0).getRule(), equalTo(PolicyRule.PERMIT));

    assertThat(policies.get(0).getScopes(), hasSize(1));
    assertThat(policies.get(0).getScopes(), hasItem(SCIM_WRITE));
  }

  @Test
  public void testUserPolicyCreationWorks() {

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected 'test' user not found"));

    IamScopePolicy policy = initDenyScopePolicy();
    policy.setAccount(testAccount);
    policy.setRule(PolicyRule.PERMIT);
    policy.setScopes(Sets.newHashSet(SCIM_WRITE));

    policyRepo.save(policy);

    List<IamScopePolicy> policies = policyRepo.findByAccount(testAccount);

    assertThat(policies, hasSize(1));

    assertThat(policies.get(0).getAccount(), equalTo(testAccount));
    assertThat(policies.get(0).getGroup(), nullValue());
    assertThat(policies.get(0).getRule(), equalTo(PolicyRule.PERMIT));

    assertThat(policies.get(0).getScopes(), hasSize(1));
    assertThat(policies.get(0).getScopes(), hasItem(SCIM_WRITE));
  }

  @Test
  public void testUserPolicyIsRemovedWhenUserIsRemoved() {

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected 'test' user not found"));

    IamScopePolicy policy = initDenyScopePolicy();
    policy.setAccount(testAccount);
    policy.setRule(PolicyRule.PERMIT);
    policy.setScopes(Sets.newHashSet(SCIM_WRITE));

    policyRepo.save(policy);

    List<IamScopePolicy> policies = policyRepo.findByAccount(testAccount);

    assertThat(policies, hasSize(1));

    accountRepo.delete(testAccount);

    assertThat(policyRepo.findByAccount(testAccount), hasSize(0));
  }

  @Test
  public void testGroupPolicyIsRemovedWhenGroupIsRemoved() {

    IamGroup emptyGroup = new IamGroup();
    emptyGroup.setName("empty");
    emptyGroup = groupService.createGroup(emptyGroup);

    IamScopePolicy policy = initDenyScopePolicy();
    policy.setGroup(emptyGroup);
    policy.setRule(PolicyRule.PERMIT);
    policy.setScopes(Sets.newHashSet(SCIM_WRITE));

    emptyGroup.getScopePolicies().add(policy);

    policyRepo.save(policy);
    groupRepo.save(emptyGroup);

    IamScopePolicy policy2 = initDenyScopePolicy();
    policy2.setGroup(emptyGroup);
    policy2.setRule(PolicyRule.DENY);
    policy2.setScopes(Sets.newHashSet(WHATEVER));

    emptyGroup.getScopePolicies().add(policy2);
    policyRepo.save(policy2);
    groupRepo.save(emptyGroup);

    List<IamScopePolicy> policies = policyRepo.findByGroup(emptyGroup);
    assertThat(policies, hasSize(2));

    groupRepo.delete(emptyGroup);
    policies = policyRepo.findByGroup(emptyGroup);
    assertThat(policies, hasSize(0));

  }

  @Test
  public void testFindEquivalentScopePolicy() {
    IamScopePolicy permitPolicy = initPermitScopePolicy();

    permitPolicy = policyRepo.save(permitPolicy);

    List<IamScopePolicy> equivalentPolicies = policyRepo.findEquivalentPolicies(permitPolicy);

    assertThat(equivalentPolicies, hasSize(1));

    IamScopePolicy denyPolicy = initDenyScopePolicy();

    equivalentPolicies = policyRepo.findEquivalentPolicies(denyPolicy);
    assertThat(equivalentPolicies, hasSize(0));
  }

  @Test
  public void testGroupEquivalentScopePolicy() {
    IamScopePolicy policy = initDenyScopePolicy();
    IamGroup analysisGroup = groupRepo.findByName("Analysis")
      .orElseThrow(() -> new AssertionError("Expected Analysis group not found"));
    
    IamGroup productionGroup = groupRepo.findByName("Production")
        .orElseThrow(() -> new AssertionError("Expected Production group not found"));

    policy.setGroup(analysisGroup);
    policy.setScopes(Sets.newHashSet(SCIM_READ, SCIM_WRITE));

    assertThat(policyRepo.findEquivalentPolicies(policy), hasSize(0));

    analysisGroup.getScopePolicies().add(policy);

    policyRepo.save(policy);

    IamScopePolicy otherPolicy = initDenyScopePolicy();
    otherPolicy.setGroup(analysisGroup);
    otherPolicy.setScopes(Sets.newHashSet(SCIM_READ));

    assertThat(policyRepo.findEquivalentPolicies(otherPolicy), hasSize(1));
    
    IamScopePolicy permitPolicy = initPermitScopePolicy();
    permitPolicy.setGroup(analysisGroup);
    permitPolicy.setScopes(Sets.newHashSet(SCIM_READ));
    
    assertThat(policyRepo.findEquivalentPolicies(permitPolicy), hasSize(0));
    
    IamScopePolicy productionPolicy =  initDenyScopePolicy();
    productionPolicy.setGroup(productionGroup);
    productionPolicy.setScopes(Sets.newHashSet(SCIM_READ));
    
    assertThat(policyRepo.findEquivalentPolicies(productionPolicy), hasSize(0));
    
    IamScopePolicy allScopesPolicy = initDenyScopePolicy();
    allScopesPolicy.setGroup(analysisGroup);
    allScopesPolicy.setScopes(Sets.newHashSet());
    
    assertThat(policyRepo.findEquivalentPolicies(allScopesPolicy), hasSize(0));
    
    
    
    
  }

  @Test
  public void testGroupEquivalentAllScopesPolicy() {
    IamScopePolicy policy = initDenyScopePolicy();
    IamGroup analysisGroup = groupRepo.findByName("Analysis")
      .orElseThrow(() -> new AssertionError("Expected Analysis group not found"));

    policy.setGroup(analysisGroup);

    List<IamScopePolicy> equivalentPolicies = policyRepo.findEquivalentPolicies(policy);

    assertThat(equivalentPolicies, hasSize(0));

    policyRepo.save(policy);

    equivalentPolicies = policyRepo.findEquivalentPolicies(policy);
    assertThat(equivalentPolicies, hasSize(1));
  }

  @Test
  public void testUserEquivalentAllScopePolicy() {
    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected 'test' user not found"));

    IamAccount adminAccount = accountRepo.findByUsername("admin")
        .orElseThrow(()-> new AssertionError("Expected 'admin' user not found"));
    
    
    IamScopePolicy policy = initDenyScopePolicy();
    policy.setAccount(testAccount);
    
    testAccount.getScopePolicies().add(policy);
    policyRepo.save(policy);

    IamScopePolicy otherPolicy = initPermitScopePolicy();
    otherPolicy.setAccount(testAccount);

    List<IamScopePolicy> equivalentPolicies = policyRepo.findEquivalentPolicies(otherPolicy);

    assertThat(equivalentPolicies, hasSize(0));

    IamScopePolicy otherDenyPolicy = initDenyScopePolicy();
    otherDenyPolicy.setAccount(adminAccount);
    
    equivalentPolicies = policyRepo.findEquivalentPolicies(otherDenyPolicy);
    assertThat(equivalentPolicies, hasSize(0));
  }
  
  @Test
  public void testUserEquivalentScopePolicy() {
    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected 'test' user not found"));

    accountRepo.findByUsername("admin")
        .orElseThrow(()-> new AssertionError("Expected 'admin' user not found"));
    
    
    IamScopePolicy policy = initDenyScopePolicy();
    policy.setAccount(testAccount);
    policy.setScopes(Sets.newHashSet(SCIM_READ, SCIM_WRITE));
    
    testAccount.getScopePolicies().add(policy);
    policyRepo.save(policy);

    IamScopePolicy otherPolicy = initPermitScopePolicy();
    otherPolicy.setAccount(testAccount);

    List<IamScopePolicy> equivalentPolicies = policyRepo.findEquivalentPolicies(otherPolicy);

    assertThat(equivalentPolicies, hasSize(0));

    IamScopePolicy otherDenyPolicy = initDenyScopePolicy();
    otherDenyPolicy.setAccount(testAccount);
    otherDenyPolicy.setScopes(Sets.newHashSet(SCIM_READ, SCIM_WRITE));
    
    equivalentPolicies = policyRepo.findEquivalentPolicies(otherDenyPolicy);
    assertThat(equivalentPolicies, hasSize(1));
    
    IamScopePolicy eqDenyPolicy = initDenyScopePolicy();
    eqDenyPolicy.setAccount(testAccount);
    eqDenyPolicy.setScopes(Sets.newHashSet(SCIM_READ, SCIM_WRITE));
    assertThat(policyRepo.findEquivalentPolicies(eqDenyPolicy), hasSize(1));
    
    
    
    eqDenyPolicy.setScopes(Sets.newHashSet(SCIM_READ));
    assertThat(policyRepo.findEquivalentPolicies(eqDenyPolicy), hasSize(1));
    eqDenyPolicy.setScopes(Sets.newHashSet(SCIM_WRITE));
    assertThat(policyRepo.findEquivalentPolicies(eqDenyPolicy), hasSize(1));
    eqDenyPolicy.setScopes(Sets.newHashSet());
    assertThat(policyRepo.findEquivalentPolicies(eqDenyPolicy), hasSize(0));
    
  }


}
