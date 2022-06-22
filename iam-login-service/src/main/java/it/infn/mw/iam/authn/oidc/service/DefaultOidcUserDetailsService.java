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
package it.infn.mw.iam.authn.oidc.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class DefaultOidcUserDetailsService implements OidcUserDetailsService {


  IamAccountRepository repo;
  InactiveAccountAuthenticationHander inactiveAccountHandler;

  @Autowired
  public DefaultOidcUserDetailsService(IamAccountRepository repo,
      InactiveAccountAuthenticationHander handler) {
    this.repo = repo;
    this.inactiveAccountHandler = handler;
  }

  List<GrantedAuthority> convertAuthorities(IamAccount a) {

    List<GrantedAuthority> authorities = new ArrayList<>();

    for (IamAuthority auth : a.getAuthorities()) {

      authorities.add(new SimpleGrantedAuthority(auth.getAuthority()));

    }
    return authorities;
  }

  protected User buildUserFromIamAccount(IamAccount account) {

    inactiveAccountHandler.handleInactiveAccount(account);

    return new User(account.getUsername(), account.getPassword(), account.isActive(), true, true,
        true, convertAuthorities(account));
  }

  protected User buildUserFromOIDCAuthentication(OIDCAuthenticationToken token) {
    String username = token.getSub();

    if (token.getUserInfo() != null && !Strings.isNullOrEmpty(token.getUserInfo().getName())) {
      username = token.getUserInfo().getName();
    }

    return new User(username, "",
        Arrays.asList(ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH));
  }

  @Override
  public Object loadUserByOIDC(OIDCAuthenticationToken token) {

    Optional<IamAccount> account = repo.findByOidcId(token.getIssuer(), token.getSub());

    if (account.isPresent()) {
      return buildUserFromIamAccount(account.get());
    }

    return buildUserFromOIDCAuthentication(token);
  }

}
