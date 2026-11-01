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
import java.util.Optional;
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
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.util.AuthenticationStateMask;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationAllowedUsers;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.persistence.model.IamAccount;

public class IamLocalAuthenticationProvider extends DaoAuthenticationProvider {

  public static final String DISABLED_AUTH_MESSAGE = "Local authentication is disabled";

  private final LocalAuthenticationAllowedUsers allowedUsers;
  private final IamAccountService accountService;
  private final IamTotpMfaService iamTotpMfaService;
  private final IamTotpMfaProperties iamTotpMfaProperties;

  private static final Predicate<GrantedAuthority> ADMIN_MATCHER =
      a -> a.getAuthority().equals("ROLE_ADMIN");
  private static final String ACR_VALUE_MFA = "https://refeds.org/profile/mfa";

  public IamLocalAuthenticationProvider(IamProperties properties, UserDetailsService uds,
      PasswordEncoder passwordEncoder, IamAccountService accountService,
      IamTotpMfaService iamTotpMfaService, IamTotpMfaProperties iamTotpMfaProperties) {
    this.allowedUsers = properties.getLocalAuthn().getEnabledFor();
    setUserDetailsService(uds);
    setPasswordEncoder(passwordEncoder);
    this.accountService = accountService;
    this.iamTotpMfaService = iamTotpMfaService;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
  }

  /**
   * Checks login eligibility, verifies credentials when necessary, and creates a token for the next
   * authentication stage.
   *
   * <p>
   * A trusted preauthenticated token skips password verification, but still undergoes
   * account-status and lockout checks. Such tokens must originate from a trusted server-side
   * authentication flow.
   *
   * <p>
   * If MFA is required, the returned token grants only {@code ROLE_PRE_AUTHENTICATED} and retains
   * the authorities needed after MFA. Otherwise, lockout state is reset with reason
   * {@link LoginLockoutResetReason#SUCCESSFUL_AUTHENTICATION}.
   *
   * @param authentication local credentials or a trusted preauthenticated token
   * @return an intermediate MFA token or a fully authenticated token
   * @throws BadCredentialsException if credentials are invalid, the account is unknown, or login is
   *         denied by account status
   * @throws DisabledException if local authentication is disallowed by configuration
   * @throws AuthenticationException if another authentication failure occurs
   */
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    Optional<IamAccount> account = accountService.findByUsername(authentication.getName());

    account.ifPresent(a -> checkLoginAllowed(a.getUuid()));

    Authentication verifiedAuthentication =
        isPreAuthenticated(authentication) ? authentication : authenticatePassword(authentication);

    IamAccount resolvedAccount = account.orElseThrow(this::badCredentials);

    checkLoginAllowed(resolvedAccount.getUuid());

    if (requiresMfa(resolvedAccount)) {
      return createPreAuthenticatedToken(verifiedAuthentication);
    }

    resetLoginLockoutAfterSuccess(resolvedAccount.getUuid());
    return createFullyAuthenticatedToken(verifiedAuthentication);
  }

  /**
   * Verifies the password and enforces the configured local-authentication policy.
   *
   * @param userDetails the loaded user details
   * @param authentication the supplied username and password
   * @throws AuthenticationException if credential verification fails
   * @throws DisabledException if local authentication is disallowed for this user
   */
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

  /**
   * Accepts extended authentication tokens used by the local login flow.
   *
   * @param authentication the authentication token class
   * @return whether the class is supported
   */
  @Override
  public boolean supports(Class<?> authentication) {
    return ExtendedAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private boolean isPreAuthenticated(Authentication authentication) {
    return authentication instanceof ExtendedAuthenticationToken token
        && token.isPreAuthenticated();
  }

  private boolean requiresMfa(IamAccount account) {
    return iamTotpMfaService.isAuthenticatorAppActive(account)
        || iamTotpMfaProperties.isMultiFactorMandatory();
  }

  /**
   * Delegates password verification and records only bad-credentials failures.
   *
   * <p>
   * Account-state errors are masked without recording another failed attempt. Genuine internal
   * authentication errors are propagated unchanged.
   */
  private Authentication authenticatePassword(Authentication authentication) {
    String username = authentication.getName();

    UsernamePasswordAuthenticationToken passwordToken = new UsernamePasswordAuthenticationToken(
        authentication.getPrincipal(), authentication.getCredentials());

    passwordToken.setDetails(authentication.getDetails());

    try {
      return super.authenticate(passwordToken);

    } catch (InternalAuthenticationServiceException e) {
      // UserDetailsService exceptions can be wrapped by DaoAuthenticationProvider.
      if (e.getCause() instanceof DisabledException || e.getCause() instanceof LockedException) {
        throw badCredentials();
      }
      throw e;

    } catch (DisabledException e) {
      // Preserve the intentional local-authentication configuration error.
      if (DISABLED_AUTH_MESSAGE.equals(e.getMessage())) {
        throw e;
      }
      throw badCredentials();

    } catch (LockedException e) {
      throw badCredentials();

    } catch (BadCredentialsException e) {
      accountService.loginFailedAttemptByUsername(username);
      throw badCredentials();
    }
  }

  /**
   * Checks account eligibility without modifying lockout state, masking account-state failures as
   * generic bad credentials.
   */
  private void checkLoginAllowed(String accountUuid) {
    AuthenticationStateMask.checkLoginAllowedOrThrowBadCredentials(accountService, accountUuid,
        getBadCredentialsMessage());
  }

  /**
   * Requests an atomic eligibility recheck and full lockout reset after successful authentication.
   * A concurrent suspension must cause the service to reject this operation.
   */
  private void resetLoginLockoutAfterSuccess(String accountUuid) {
    AuthenticationStateMask.resetLoginLockoutOrThrowBadCredentials(accountService, accountUuid,
        LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION, getBadCredentialsMessage());
  }

  private BadCredentialsException badCredentials() {
    return new BadCredentialsException(getBadCredentialsMessage());
  }

  private String getBadCredentialsMessage() {
    return messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
        "Bad credentials");
  }

  /**
   * Creates an intermediate token that permits MFA completion while retaining the authorities to
   * grant once MFA succeeds.
   */
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
    token.setDetails(authentication.getDetails());

    return token;
  }
}
