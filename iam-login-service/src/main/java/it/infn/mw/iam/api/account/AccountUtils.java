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
package it.infn.mw.iam.api.account;

import static java.util.Objects.isNull;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
@Component
public class AccountUtils {
  IamAccountRepository accountRepo;

  @Autowired
  public AccountUtils(IamAccountRepository accountRepo) {
    this.accountRepo = accountRepo;
  }

  public boolean isRegisteredUser(Authentication auth) {
    if (auth == null || auth.getAuthorities() == null) {
      return false;
    }

    return auth.getAuthorities().contains(Authorities.ROLE_USER);
  }

  public boolean isAdmin(Authentication auth) {
    if (auth == null || auth.getAuthorities() == null) {
      return false;
    }

    return auth.getAuthorities().contains(Authorities.ROLE_ADMIN);
  }

  public boolean isAuthenticated() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    return isAuthenticated(auth);
  }

  public boolean isAuthenticated(Authentication auth) {
    return !(isNull(auth) || auth instanceof AnonymousAuthenticationToken);
  }

  public Optional<IamAccount> getAuthenticatedUserAccount(Authentication authn) {
    if (!isAuthenticated(authn)) {
      return Optional.empty();
    }

    Authentication userAuthn = authn;
    
    if (authn instanceof OAuth2Authentication) {
      OAuth2Authentication oauth = (OAuth2Authentication) authn;
      if (oauth.getUserAuthentication() == null) {
        return Optional.empty();
      }
      userAuthn = oauth.getUserAuthentication();
    }

    return accountRepo.findByUsername(userAuthn.getName());

  }

  public Optional<IamAccount> getAuthenticatedUserAccount() {
    
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
 
    return getAuthenticatedUserAccount(auth);
  }
  
  public Optional<IamAccount> getByAccountId(String accountId){
    return accountRepo.findByUuid(accountId);
  }
}
