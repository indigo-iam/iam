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
import java.util.Map;
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

import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorPolicy;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationAllowedUsers;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class IamLocalAuthenticationProvider extends DaoAuthenticationProvider {

  public static final String DISABLED_AUTH_MESSAGE = "Local authentication is disabled";

  private final LocalAuthenticationAllowedUsers allowedUsers;
  private final IamAccountRepository accountRepo;
  private final MultiFactorPolicy multiFactorPolicy;

  private static final Predicate<GrantedAuthority> ADMIN_MATCHER =
      a -> a.getAuthority().equals("ROLE_ADMIN");
  private static final String ACR_VALUE_MFA = "https://refeds.org/profile/mfa";

  public IamLocalAuthenticationProvider(IamProperties properties, UserDetailsService uds,
      PasswordEncoder passwordEncoder, IamAccountRepository accountRepo,
      MultiFactorPolicy multiFactorPolicy) {
    this.allowedUsers = properties.getLocalAuthn().getEnabledFor();
    setUserDetailsService(uds);
    setPasswordEncoder(passwordEncoder);
    this.accountRepo = accountRepo;
    this.multiFactorPolicy = multiFactorPolicy;
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
    // A token that was already pre-authenticated (by this provider on a previous request, or by
    // another mechanism such as X.509) is only re-validated, never re-authenticated
    ExtendedAuthenticationToken preAuthenticatedToken = null;
    if (authentication instanceof ExtendedAuthenticationToken extendedAuthenticationToken
        && extendedAuthenticationToken.isPreAuthenticated()) {
      preAuthenticatedToken = extendedAuthenticationToken;
    }
    boolean isPreAuthenticated = preAuthenticatedToken != null;

    // If not preauthenticated then the first step is to validate the default login credentials.
    // Therefore, we convert the
    // authentication to a UsernamePasswordAuthenticationToken and super(authenticate) in the
    // default manner
    if (!isPreAuthenticated) {
      UsernamePasswordAuthenticationToken userpassToken = new UsernamePasswordAuthenticationToken(
          authentication.getPrincipal(), authentication.getCredentials());
      authentication = super.authenticate(userpassToken);
    }

    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));

    // The password check performed this control on every request; a pre-authenticated token is
    // re-validated without it, so an account disabled in the meantime must still be stopped here
    if (isPreAuthenticated && !account.isActive()) {
      throw new DisabledException("User '" + account.getUsername() + "' is not active.");
    }

    ExtendedAuthenticationToken token;

    Set<IamAuthenticationMethodReference> refs = new HashSet<>();
    if (isPreAuthenticated) {
      // The references describe how the first factor was verified: keep them
      if (preAuthenticatedToken.getAuthenticationMethodReferences() != null) {
        refs.addAll(preAuthenticatedToken.getAuthenticationMethodReferences());
      }
    } else {
      // We have just completed an authentication with the user's password. Therefore, we add "pwd"
      // to the list of authentication method references.
      refs.add(new IamAuthenticationMethodReference(PASSWORD.getValue()));
    }

    // A second factor is active on the account, or required by the policy: the user is only
    // pre-authenticated until it is verified (or enrolled)
    if (multiFactorPolicy.isMandatory() || multiFactorPolicy.isActive(account)) {
      List<GrantedAuthority> currentAuthorities = new ArrayList<>();
      // Add PRE_AUTHENTICATED role to the user. This grants them access to the /iam/verify endpoint
      currentAuthorities.add(Authorities.ROLE_PRE_AUTHENTICATED);

      // Retrieve the authorities that are assigned to this user when they are fully authenticated.
      // A token that was already pre-authenticated only carries the PRE_AUTHENTICATED role: the
      // authorities to grant after the second factor are the ones it was built with
      Set<GrantedAuthority> fullyAuthenticatedAuthorities = new HashSet<>();
      if (isPreAuthenticated && preAuthenticatedToken.getFullyAuthenticatedAuthorities() != null) {
        fullyAuthenticatedAuthorities
          .addAll(preAuthenticatedToken.getFullyAuthenticatedAuthorities());
      } else {
        fullyAuthenticatedAuthorities.addAll(authentication.getAuthorities());
      }

      // Construct a new authentication object for the PRE_AUTHENTICATED user.
      token = new ExtendedAuthenticationToken(authentication.getPrincipal(),
          authentication.getCredentials(), currentAuthorities);
      token.setAuthenticated(false);
      // The password has been verified: until the second factor is, every request re-validates
      // this token through the pre-authenticated path above, without a second password check
      token.setPreAuthenticated(true);
      token.setAuthenticationMethodReferences(refs);
      token.setFullyAuthenticatedAuthorities(fullyAuthenticatedAuthorities);
      token.setDetails(Map.of("acr", ACR_VALUE_MFA));
    } else {
      // MFA is not enabled on this account, construct a new authentication object for the FULLY
      // AUTHENTICATED user, granting their normal authorities (a pre-authenticated token only
      // carries the PRE_AUTHENTICATED role: its full authorities were kept aside)
      token = new ExtendedAuthenticationToken(authentication.getPrincipal(),
          authentication.getCredentials(),
          isPreAuthenticated && preAuthenticatedToken.getFullyAuthenticatedAuthorities() != null
              ? preAuthenticatedToken.getFullyAuthenticatedAuthorities()
              : authentication.getAuthorities());
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
