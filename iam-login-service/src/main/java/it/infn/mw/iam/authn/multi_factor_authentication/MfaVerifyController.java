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
package it.infn.mw.iam.authn.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.X509;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorPolicy;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.authn.util.AuthenticationUtils;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Presents the step-up authentication page for verifying identity after successful username +
 * password authentication. Only accessible if the user is pre-authenticated, i.e. has authenticated
 * with username + password but not fully authenticated yet
 */
@Controller
public class MfaVerifyController {

  public static final String MFA_VERIFY_URL = "/iam/verify";
  public static final String MFA_ACTIVATE_URL = "/iam/mfa/activate";
  public static final String ENROLMENT_NOT_REQUIRED_MESSAGE =
      "The account is not required to enrol a second factor";

  final IamAccountRepository accountRepository;
  private final IamTotpMfaService iamTotpMfaService;
  private final IamPasskeyService passkeyService;
  private final AccountUtils accountUtils;
  private final MultiFactorPolicy multiFactorPolicy;

  public MfaVerifyController(IamAccountRepository accountRepository,
      IamTotpMfaService iamTotpMfaService, IamPasskeyService passkeyService,
      AccountUtils accountUtils, MultiFactorPolicy multiFactorPolicy) {
    this.accountRepository = accountRepository;
    this.iamTotpMfaService = iamTotpMfaService;
    this.passkeyService = passkeyService;
    this.accountUtils = accountUtils;
    this.multiFactorPolicy = multiFactorPolicy;
  }

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @GetMapping(value = MFA_VERIFY_URL)
  public String getVerifyMfaView(Authentication authentication, ModelMap model) {
    IamAccount account = accountRepository.findByUsername(authentication.getName())
      .orElseThrow(() -> NoSuchAccountError.forUsername(authentication.getName()));
    // Each flag enables the form of a factor the user may verify with
    model.addAttribute("isAuthenticatorAppActive",
        iamTotpMfaService.isAuthenticatorAppActive(account)
            && !multiFactorPolicy.onlyPasskeyAccepted(account));
    model.addAttribute("isPasskeyActive", passkeyService.isPasskeyActive(account));

    if (authentication instanceof PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken) {
      setAuthentication(preAuthenticatedAuthenticationToken, account);
    }
    return "iam/verify-mfa";
  }

  /**
   * An X.509 login arrives here as a PreAuthenticatedAuthenticationToken holding only the
   * PRE_AUTHENTICATED role: it is turned into the pre-authenticated token the MFA verification
   * providers expect, carrying the account authorities to grant once the second factor is verified
   */
  private void setAuthentication(PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken,
      IamAccount account) {
    Set<GrantedAuthority> authenticatedAuthorities = new HashSet<>(
        preAuthenticatedAuthenticationToken.getAuthorities());
    if (preAuthenticatedAuthenticationToken.getPrincipal() instanceof User user) {
      ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(user.getUsername(), "SECRET",
          authenticatedAuthorities);
      token.setAuthenticated(false);
      token.setAuthenticationMethodReferences(Set.of(
          new IamAuthenticationMethodReference(X509.getValue())));
      token.setPreAuthenticated(true);
      token.setFullyAuthenticatedAuthorities(
          new HashSet<>(AuthenticationUtils.convertIamAccountAuthorities(account)));
      SecurityContextHolder.getContext().setAuthentication(token);
    }
  }

  /**
   * The enrolment page is meant for pre-authenticated users enrolling their first factor. A fully
   * authenticated user reaches it only when a mandatory passkey is still missing (e.g. after the
   * last login with the authenticator app): the EnforceMfaFilter sends them here
   */
  @PreAuthorize("hasAnyRole('PRE_AUTHENTICATED', 'USER')")
  @GetMapping(value = MFA_ACTIVATE_URL)
  public String getActivateMfaView(Authentication authentication) {
    Optional<IamAccount> account = accountRepository.findByUsername(authentication.getName());

    if (accountUtils.isPreAuthenticated(authentication)) {
      // A pre-authenticated user who already owns a factor verifies it first: enrolling another
      // one is refused until then (external logins can reach this page through the enforcement
      // filter before verifying)
      if (account.isPresent() && multiFactorPolicy.isActive(account.get())) {
        return "redirect:" + MFA_VERIFY_URL;
      }
      return "iam/activateMfa";
    }

    // A fully authenticated user is sent here by the enforcement filter when a mandatory factor is
    // missing; the same condition decides whether the page may open at all
    IamAccount fullyAuthenticated =
        account.orElseThrow(() -> NoSuchAccountError.forUsername(authentication.getName()));
    if (!multiFactorPolicy.requiresEnrolment(fullyAuthenticated)) {
      throw new AccessDeniedException(ENROLMENT_NOT_REQUIRED_MESSAGE);
    }
    return "iam/activateMfa";
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(NoSuchAccountError.class)
  @ResponseBody
  public ErrorDTO handleNoSuchAccountError(NoSuchAccountError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
