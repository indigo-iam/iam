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
package it.infn.mw.iam.authn.x509;

import java.util.Arrays;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
public class IamX509AuthenticationUserDetailService
    implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

  public static final Logger LOG =
      LoggerFactory.getLogger(IamX509AuthenticationUserDetailService.class);

  public static final SimpleGrantedAuthority X509_AUTHORITY =
      new SimpleGrantedAuthority("ROLE_X509");

  IamAccountRepository accountRepository;
  InactiveAccountAuthenticationHander inactiveAccountHandler;

  @Autowired
  public IamX509AuthenticationUserDetailService(IamAccountRepository accountRepository,
      InactiveAccountAuthenticationHander handler) {
    this.accountRepository = accountRepository;
    this.inactiveAccountHandler = handler;
  }

  protected User buildUserFromIamAccount(IamAccount account) {
    return AuthenticationUtils.userFromIamAccount(account, X509_AUTHORITY);
  }

  protected User buildUnknownUser(PreAuthenticatedAuthenticationToken token) {
    return new User(token.getName(), "", Arrays.asList(X509_AUTHORITY));
  }


  @Override
  public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) {

    String principal = (String) token.getPrincipal();

    LOG.debug("Loading IAM account for X.509 principal '{}'", principal);

    Optional<IamAccount> account = accountRepository.findByCertificateSubject(principal);

    if (account.isPresent()) {
      LOG.debug("Found IAM account {} linked to principal '{}'", account.get().getUuid(), principal);
      return buildUserFromIamAccount(account.get());
    } else {
      return buildUnknownUser(token);
    }
  }

}
