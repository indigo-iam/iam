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
package it.infn.mw.iam.core;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationAllowedUsers;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthenticationMethodReference;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class IamLocalAuthenticationProvider extends DaoAuthenticationProvider {

  public static final Logger LOG = LoggerFactory.getLogger(IamLocalAuthenticationProvider.class);

  public static final String DISABLED_AUTH_MESSAGE = "Local authentication is disabled";

  private final LocalAuthenticationAllowedUsers allowedUsers;

  private static final Predicate<GrantedAuthority> ADMIN_MATCHER =
      a -> a.getAuthority().equals("ROLE_ADMIN");

  private final IamAccountRepository accountRepo;

  public IamLocalAuthenticationProvider(IamProperties properties, UserDetailsService uds,
      PasswordEncoder passwordEncoder, IamAccountRepository accountRepo) {
    this.allowedUsers = properties.getLocalAuthn().getEnabledFor();
    setUserDetailsService(uds);
    setPasswordEncoder(passwordEncoder);
    this.accountRepo = accountRepo;
  }

  @Override
  protected void additionalAuthenticationChecks(UserDetails userDetails,
      UsernamePasswordAuthenticationToken authentication) {

    super.additionalAuthenticationChecks(userDetails, authentication);
    if (LocalAuthenticationAllowedUsers.NONE.equals(allowedUsers)
        || (LocalAuthenticationAllowedUsers.VO_ADMINS.equals(allowedUsers)
            && userDetails.getAuthorities().stream().noneMatch(ADMIN_MATCHER))) {
      throw new DisabledException(DISABLED_AUTH_MESSAGE);
    }

    // Used local authentication (username and password) only, so add pwd as method of
    // authentication. This ensures the amr flag is properly set in an id_token, if OIDC used
    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));
    IamAuthenticationMethodReference pwd = new IamAuthenticationMethodReference();
    pwd.setAccount(account);
    pwd.setName("pwd");
    Set<IamAuthenticationMethodReference> refs = new HashSet<>(Arrays.asList(pwd));
    account.setAuthenticationMethodReferences(refs);
    accountRepo.save(account);
  }
}
