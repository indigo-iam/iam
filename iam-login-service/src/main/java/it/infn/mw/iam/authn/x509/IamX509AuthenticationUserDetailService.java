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

import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorPolicy;
import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.util.AuthenticationUtils;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
public class IamX509AuthenticationUserDetailService
    implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

  public static final Logger LOG =
      LoggerFactory.getLogger(IamX509AuthenticationUserDetailService.class);

  private static final String ACR_VALUE_MFA = "https://refeds.org/profile/mfa";

  IamAccountRepository accountRepository;
  InactiveAccountAuthenticationHander inactiveAccountHandler;
  private final MultiFactorPolicy multiFactorPolicy;

  public IamX509AuthenticationUserDetailService(IamAccountRepository accountRepository,
      InactiveAccountAuthenticationHander handler, MultiFactorPolicy multiFactorPolicy) {
    this.accountRepository = accountRepository;
    this.inactiveAccountHandler = handler;
    this.multiFactorPolicy = multiFactorPolicy;
  }

  protected UserDetails buildUserFromIamAccount(IamAccount account,
      PreAuthenticatedAuthenticationToken token) {

    inactiveAccountHandler.handleInactiveAccount(account);

    if (multiFactorPolicy.isMandatory() || multiFactorPolicy.isActive(account)) {
      token.setDetails(Map.of("acr", ACR_VALUE_MFA));
      return withPreAuthenticatedRole(AuthenticationUtils.userFromIamAccount(account));
    }

    return AuthenticationUtils.userFromIamAccount(account);
  }

  /**
   * Until the second factor is verified the user only holds the PRE_AUTHENTICATED role, which
   * grants access to the /iam/verify endpoint: the account authorities are granted by the
   * verification step (see MfaVerifyController), never added to the persistent account
   */
  private UserDetails withPreAuthenticatedRole(User user) {
    return new User(user.getUsername(), user.getPassword(),
        Set.of(Authorities.ROLE_PRE_AUTHENTICATED));
  }

  @Override
  public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token)
      throws UsernameNotFoundException {

    String principal = (String) token.getPrincipal();

    LOG.debug("Loading IAM account for X.509 principal '{}'", principal);

    IamAccount account = accountRepository.findByCertificateSubject(principal).orElseThrow(() -> {
      final String msg = String.format("No IAM account found for X.509 principal '%s'", principal);
      LOG.debug(msg);
      return new UsernameNotFoundException(msg);
    });

    LOG.debug("Found IAM account {} linked to principal '{}'", account, principal);

    return buildUserFromIamAccount(account, token);

  }

}
