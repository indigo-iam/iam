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
package it.infn.mw.iam.api.scope_policy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Component
public class DefaultScopePolicyConverter implements IamScopePolicyConverter {

  private final ScimResourceLocationProvider resourceLocationProvider;
  private final IamAccountRepository accountRepo;
  private final IamGroupRepository groupRepo;

  @Autowired
  public DefaultScopePolicyConverter(ScimResourceLocationProvider locationProvider,
      IamAccountRepository accountRepo, IamGroupRepository groupRepo) {
    this.resourceLocationProvider = locationProvider;
    this.accountRepo = accountRepo;
    this.groupRepo = groupRepo;
  }

  public ScopePolicyDTO fromModel(IamScopePolicy sp) {
    ScopePolicyDTO dto = new ScopePolicyDTO();

    dto.setId(sp.getId());
    dto.setCreationTime(sp.getCreationTime());
    dto.setLastUpdateTime(sp.getLastUpdateTime());
    dto.setDescription(sp.getDescription());
    dto.setRule(sp.getRule().name());
    dto.setMatchingPolicy(sp.getMatchingPolicy().name());

    if (!sp.getScopes().isEmpty()) {
      dto.setScopes(Sets.newHashSet());
      dto.getScopes().addAll(sp.getScopes());
    }

    if (sp.getAccount() != null) {

      IamAccountRefDTO ar = new IamAccountRefDTO();
      ar.setUuid(sp.getAccount().getUuid());
      ar.setUsername(sp.getAccount().getUsername());
      ar.setLocation(resourceLocationProvider.userLocation(sp.getAccount().getUuid()));

      dto.setAccount(ar);

    }

    if (sp.getGroup() != null) {
      GroupRefDTO gr = new GroupRefDTO();

      gr.setLocation(resourceLocationProvider.groupLocation(sp.getGroup().getUuid()));
      gr.setName(sp.getGroup().getName());
      gr.setUuid(sp.getGroup().getUuid());

      dto.setGroup(gr);

    }
    return dto;
  }

  public IamScopePolicy toModel(ScopePolicyDTO sp) {

    IamScopePolicy scopePolicy = new IamScopePolicy();

    scopePolicy.setDescription(sp.getDescription());
    scopePolicy.setRule(PolicyRule.valueOf(sp.getRule()));
    scopePolicy.setMatchingPolicy(MatchingPolicy.valueOf(sp.getMatchingPolicy()));

    if (sp.getScopes() != null) {
      scopePolicy.getScopes().addAll(sp.getScopes());
    }

    if (sp.getAccount() != null) {
      IamAccount account = accountRepo.findByUuid(sp.getAccount().getUuid())
        .orElseThrow(() -> new InvalidScopePolicyError(
            "No account found for UUID: " + sp.getAccount().getUuid()));
      scopePolicy.setAccount(account);
    }

    if (sp.getGroup() != null) {
      IamGroup group = groupRepo.findByUuid(sp.getGroup().getUuid()).orElseThrow(
          () -> new InvalidScopePolicyError("No group found for UUID: " + sp.getGroup().getUuid()));

      scopePolicy.setGroup(group);
    }

    return scopePolicy;
  }

}
