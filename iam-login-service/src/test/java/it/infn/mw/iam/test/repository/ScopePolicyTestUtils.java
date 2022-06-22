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

import java.util.Date;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import it.infn.mw.iam.api.scope_policy.ScopePolicyDTO;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;

public class ScopePolicyTestUtils {
  
  public static final String SCIM_READ = "scim:read";
  public static final String SCIM_WRITE = "scim:write";
  public static final String OPENID = "openid";
  public static final String PROFILE = "profile";
  public static final String WHATEVER = "whatever";
  
  protected ScopePolicyDTO initPermitScopePolicyDTO(){
    ScopePolicyDTO dto = new ScopePolicyDTO();
    dto.setRule(PolicyRule.PERMIT.name());
    return dto;
  }
  
  protected ScopePolicyDTO initDenyScopePolicyDTO(){
    ScopePolicyDTO dto = new ScopePolicyDTO();
    dto.setRule(PolicyRule.DENY.name());
    return dto;
  }
  
  private IamScopePolicy initScopePolicy() {
    Date now = new Date();
    IamScopePolicy p = new IamScopePolicy();
    p.setCreationTime(now);
    p.setLastUpdateTime(now);
    return p;
  }
  protected IamScopePolicy initDenyScopePolicy(){
    IamScopePolicy p = initScopePolicy();
    p.setRule(PolicyRule.DENY);
    return p;
  }
  
  protected IamScopePolicy initPermitScopePolicy(){
    IamScopePolicy p = initScopePolicy();
    p.setRule(PolicyRule.PERMIT);
    return p;
  }
  
  public Authentication anonymousAuthenticationToken() {
    return new AnonymousAuthenticationToken("key", "anonymous",
        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
  }

}
