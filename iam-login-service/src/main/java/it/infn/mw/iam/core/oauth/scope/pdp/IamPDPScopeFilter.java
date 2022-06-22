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
package it.infn.mw.iam.core.oauth.scope.pdp;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
@Component
@ConditionalOnProperty(name = "iam.enableScopeAuthz", havingValue = "true")
public class IamPDPScopeFilter implements IamScopeFilter {

  final ScopePolicyPDP pdp;
  final IamAccountRepository accountRepo;

  @Autowired
  public IamPDPScopeFilter(ScopePolicyPDP pdp, IamAccountRepository accountRepo) {
    this.pdp = pdp;
    this.accountRepo = accountRepo;
  }

  protected Optional<IamAccount> resolveIamAccount(Authentication authn) {
    
    if (authn == null){
      return Optional.empty();
    }
    
    Authentication userAuthn = authn;
    
    if (authn instanceof OAuth2Authentication){
      userAuthn = ((OAuth2Authentication) authn).getUserAuthentication();
    }
    
    if (userAuthn == null) {
      return Optional.empty();
    }

    String principalName = authn.getName();
    return accountRepo.findByUsername(principalName);
  }

  @Override
  public void filterScopes(Set<String> scopes, Authentication authn) {
    
    Optional<IamAccount> maybeAccount = resolveIamAccount(authn);

    if (maybeAccount.isPresent()) {
      Set<String> filteredScopes =
          pdp.filterScopes(scopes, maybeAccount.get());
      
      scopes.retainAll(filteredScopes);
    }

  }

}
