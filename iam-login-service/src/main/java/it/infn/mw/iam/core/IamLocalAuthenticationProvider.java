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

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.PASSWORD;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationAllowedUsers;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

public class IamLocalAuthenticationProvider extends DaoAuthenticationProvider {

  public static final String DISABLED_AUTH_MESSAGE = "Local authentication is disabled";

  private final LocalAuthenticationAllowedUsers allowedUsers;
  private final IamAccountRepository accountRepo;
  private final IamTotpMfaRepository totpMfaRepository;

  private static final Predicate<GrantedAuthority> ADMIN_MATCHER =
      a -> a.getAuthority().equals("ROLE_ADMIN");

  public IamLocalAuthenticationProvider(IamProperties properties, UserDetailsService uds,
      PasswordEncoder passwordEncoder, IamAccountRepository accountRepo,
      IamTotpMfaRepository totpMfaRepository) {
    this.allowedUsers = properties.getLocalAuthn().getEnabledFor();
    setUserDetailsService(uds);
    setPasswordEncoder(passwordEncoder);
    this.accountRepo = accountRepo;
    this.totpMfaRepository = totpMfaRepository;
  }

  /**
   * <p>
   * Overriding this to accommodate the ExtendedAuthenticationToken.
   * 
   * <p>
   * First, we authenticate the username and password. Then we check if MFA is enabled on the
   * account. If so, we set a {@code PRE_AUTHENTICATED} role on the user so they may be navigated to
   * an additional authentication step. Otherwise, create a full authentication object.
   */
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    // The first step is to validate the default login credentials. Therefore, we convert the
    // authentication to a UsernamePasswordAuthenticationToken and super(authenticate) in the
    // default manner
    UsernamePasswordAuthenticationToken userpassToken = new UsernamePasswordAuthenticationToken(
        authentication.getPrincipal(), authentication.getCredentials());
    authentication = super.authenticate(userpassToken);

    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));

    ExtendedAuthenticationToken token;

    // We have just completed an authentication with the user's password. Therefore, we add "pwd" to
    // the list of authentication method references.
    IamAuthenticationMethodReference pwd =
        new IamAuthenticationMethodReference(PASSWORD.getValue());
    Set<IamAuthenticationMethodReference> refs = new HashSet<>();
    refs.add(pwd);

    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);

    // Checking to see if we can find an active MFA secret attached to the user's account. If so,
    // MFA is enabled on the account
    if (totpMfaOptional.isPresent() && totpMfaOptional.get().isActive()) {
      List<GrantedAuthority> currentAuthorities = new ArrayList<>();
      // Add PRE_AUTHENTICATED role to the user. This grants them access to the /iam/verify endpoint
      currentAuthorities.add(Authorities.ROLE_PRE_AUTHENTICATED);

      // Retrieve the authorities that are assigned to this user when they are fully authenticated
      Set<GrantedAuthority> fullyAuthenticatedAuthorities = new HashSet<>();
      for (GrantedAuthority a : authentication.getAuthorities()) {
        fullyAuthenticatedAuthorities.add(a);
      }

      // Construct a new authentication object for the PRE_AUTHENTICATED user.
      token = new ExtendedAuthenticationToken(authentication.getPrincipal(),
          authentication.getCredentials(), currentAuthorities);
      token.setAuthenticated(false);
      token.setAuthenticationMethodReferences(refs);
      token.setFullyAuthenticatedAuthorities(fullyAuthenticatedAuthorities);
    } else {
      // MFA is not enabled on this account, construct a new authentication object for the FULLY
      // AUTHENTICATED user, granting their normal authorities
      token = new ExtendedAuthenticationToken(authentication.getPrincipal(),
          authentication.getCredentials(), authentication.getAuthorities());
      token.setAuthenticationMethodReferences(refs);
      token.setAuthenticated(true);
    }

    return token;
  }

  @Override
  protected void additionalAuthenticationChecks(UserDetails userDetails,
      UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    super.additionalAuthenticationChecks(userDetails, authentication);
    if (LocalAuthenticationAllowedUsers.NONE.equals(allowedUsers)
        || (LocalAuthenticationAllowedUsers.VO_ADMINS.equals(allowedUsers)
            && userDetails.getAuthorities().stream().noneMatch(ADMIN_MATCHER))) {
      throw new DisabledException(DISABLED_AUTH_MESSAGE);
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return (ExtendedAuthenticationToken.class.isAssignableFrom(authentication));
  }
}
