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

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.authn.lockout.LoginLockoutService;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationAllowedUsers;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class IamLocalAuthenticationProvider extends DaoAuthenticationProvider {

  public static final String DISABLED_AUTH_MESSAGE = "Local authentication is disabled";

  private final LocalAuthenticationAllowedUsers allowedUsers;
  private final IamAccountRepository accountRepo;
  private final IamTotpMfaService iamTotpMfaService;
  private final IamTotpMfaProperties iamTotpMfaProperties;
  private final LoginLockoutService lockoutService;

  private static final Predicate<GrantedAuthority> ADMIN_MATCHER =
      a -> a.getAuthority().equals("ROLE_ADMIN");
  private static final String ACR_VALUE_MFA = "https://refeds.org/profile/mfa";

  public IamLocalAuthenticationProvider(IamProperties properties, UserDetailsService uds,
      PasswordEncoder passwordEncoder, IamAccountRepository accountRepo,
      IamTotpMfaService iamTotpMfaService, IamTotpMfaProperties iamTotpMfaProperties,
      LoginLockoutService lockoutService) {
    this.allowedUsers = properties.getLocalAuthn().getEnabledFor();
    setUserDetailsService(uds);
    setPasswordEncoder(passwordEncoder);
    this.accountRepo = accountRepo;
    this.iamTotpMfaService = iamTotpMfaService;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
    this.lockoutService = lockoutService;
  }

  /**
   * Authenticates local credentials and creates an authentication token reflecting the required
   * authentication stage.
   *
   * <p>
   * Unless the supplied token is already pre-authenticated, checks account lockout and validates
   * the username and password. Invalid credentials and inactive accounts are recorded as failed
   * attempts, while account lockout and inactive-account errors are masked as bad credentials.
   *
   * <p>
   * If an authenticator app is active for the account or MFA is mandatory, returns a
   * pre-authenticated token granting only {@code ROLE_PRE_AUTHENTICATED}, retaining the user's
   * authorities for completion of MFA. Failed attempts are not reset while MFA is pending.
   * Otherwise, resets failed attempts and returns a fully authenticated token with the user's
   * authorities.
   *
   * <p>
   * Both returned token types include the password authentication method reference ({@code pwd}).
   *
   * @param authentication the local credentials or an already pre-authenticated token
   * @return a pre-authenticated token if MFA is required, or a fully authenticated token otherwise
   * @throws AuthenticationException if authentication fails, local authentication is disallowed, or
   *         the account cannot be found
   */
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    Authentication verifiedAuthentication =
        isPreAuthenticated(authentication) ? authentication : authenticatePassword(authentication);

    IamAccount account = accountRepo.findByUsername(verifiedAuthentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));

    if (requiresMfa(account)) {
      return createPreAuthenticatedToken(verifiedAuthentication);
    }

    lockoutService.resetFailedAttempts(verifiedAuthentication.getName());
    return createFullyAuthenticatedToken(verifiedAuthentication);
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

  private BadCredentialsException badCredentials() {
    return new BadCredentialsException(messages
      .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return (ExtendedAuthenticationToken.class.isAssignableFrom(authentication));
  }

  private boolean isPreAuthenticated(Authentication authentication) {
    return authentication instanceof ExtendedAuthenticationToken token
        && token.isPreAuthenticated();
  }

  private boolean requiresMfa(IamAccount account) {
    return iamTotpMfaService.isAuthenticatorAppActive(account)
        || iamTotpMfaProperties.isMultiFactorMandatory();
  }

  private Authentication authenticatePassword(Authentication authentication) {

    String username = authentication.getName();
    checkAccountLockout(username);

    UsernamePasswordAuthenticationToken passwordToken = new UsernamePasswordAuthenticationToken(
        authentication.getPrincipal(), authentication.getCredentials());

    try {
      return super.authenticate(passwordToken);
    } catch (InternalAuthenticationServiceException e) {
      throw handleInternalAuthenticationFailure(username, e);
    } catch (DisabledException e) {
      throw handleDisabledAccount(username, e);
    } catch (BadCredentialsException e) {
      lockoutService.recordFailedAttempt(username);
      throw e;
    }
  }

  private void checkAccountLockout(String username) {
    try {
      lockoutService.checkIamAccountLockout(username);
    } catch (LockedException e) {
      throw badCredentials();
    }
  }

  private AuthenticationException handleInternalAuthenticationFailure(String username,
      InternalAuthenticationServiceException exception) {

    // Mask inactive accounts, but preserve genuine internal errors.
    if (exception.getCause() instanceof DisabledException) {
      return recordFailedAttempt(username);
    }

    return exception;
  }

  private AuthenticationException handleDisabledAccount(String username,
      DisabledException exception) {

    // Preserve the intentional configuration message.
    if (DISABLED_AUTH_MESSAGE.equals(exception.getMessage())) {
      return exception;
    }

    return recordFailedAttempt(username);
  }

  private BadCredentialsException recordFailedAttempt(String username) {
    lockoutService.recordFailedAttempt(username);
    return badCredentials();
  }

  private ExtendedAuthenticationToken createPreAuthenticatedToken(Authentication authentication) {

    ExtendedAuthenticationToken token =
        createPasswordToken(authentication, List.of(Authorities.ROLE_PRE_AUTHENTICATED));

    token.setAuthenticated(false);
    token.setPreAuthenticated(true);
    token.setFullyAuthenticatedAuthorities(new HashSet<>(authentication.getAuthorities()));
    token.setDetails(Map.of("acr", ACR_VALUE_MFA));

    return token;
  }

  private ExtendedAuthenticationToken createFullyAuthenticatedToken(Authentication authentication) {

    ExtendedAuthenticationToken token =
        createPasswordToken(authentication, authentication.getAuthorities());

    token.setAuthenticated(true);
    return token;
  }

  private ExtendedAuthenticationToken createPasswordToken(Authentication authentication,
      Collection<? extends GrantedAuthority> authorities) {

    ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(
        authentication.getPrincipal(), authentication.getCredentials(), authorities);

    Set<IamAuthenticationMethodReference> refs = new HashSet<>();
    refs.add(new IamAuthenticationMethodReference(PASSWORD.getValue()));
    token.setAuthenticationMethodReferences(refs);

    return token;
  }
}
