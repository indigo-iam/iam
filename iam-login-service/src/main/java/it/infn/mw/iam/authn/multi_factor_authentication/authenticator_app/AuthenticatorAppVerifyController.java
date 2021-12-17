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
package it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app;

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import dev.samstevens.totp.code.CodeVerifier;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.CodeDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.authn.multi_factor_authentication.error.MultiFactorAuthenticationError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;

@Controller
public class AuthenticatorAppVerifyController {

  public static final String VERIFY_CODE_URL = MFA_VERIFY_URL + "/authenticator-app/code";
  public static final String VERIFY_RECOVERY_CODE_URL =
      MFA_VERIFY_URL + "/authenticator-app/recovery-code";

  private final AccountUtils accountUtils;
  private final CodeVerifier codeVerifier;
  private final AuthenticationEventPublisher eventPublisher;

  // TODO - step up authentication page can't read SPRING_SECURITY_LAST_EXCEPTION.message to display
  // "Bad code" error. Fix this and use
  // ExternalAuthenticationHandlerSupport.saveAuthenticationErrorInSession() as a reference

  @Autowired
  public AuthenticatorAppVerifyController(AccountUtils accountUtils, CodeVerifier codeVerifier,
      AuthenticationEventPublisher eventPublisher) {
    this.accountUtils = accountUtils;
    this.codeVerifier = codeVerifier;
    this.eventPublisher = eventPublisher;
  }

  private void authenticationSuccessEvent(Authentication authentication) {
    eventPublisher.publishAuthenticationSuccess(authentication);
  }

  private void authenticationFailureEvent(AuthenticationException exception,
      Authentication authentication) {
    eventPublisher.publishAuthenticationFailure(exception, authentication);
  }

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @RequestMapping(method = RequestMethod.POST, path = VERIFY_CODE_URL)
  public String verifyCode(@ModelAttribute @Valid CodeDTO code, BindingResult validationResult,
      Authentication authentication, RedirectAttributes redirectAttributes) {
    if (validationResult.hasErrors()) {
      MultiFactorAuthenticationError error = new MultiFactorAuthenticationError("Bad MFA code");
      authenticationFailureEvent(error, authentication);
      redirectAttributes.addAttribute("error", "failure");
      return "redirect:/iam/verify";
    }

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new MultiFactorAuthenticationError("Account not found"));

    if (!codeVerifier.isValidCode(account.getTotpMfa().getSecret(), code.getCode())) {
      MultiFactorAuthenticationError error = new MultiFactorAuthenticationError("Bad MFA code");
      authenticationFailureEvent(error, authentication);
      redirectAttributes.addAttribute("error", "failure");
      return "redirect:/iam/verify";
    }

    SecurityContext sc = SecurityContextHolder.getContext();
    List<GrantedAuthority> updatedAuthorities =
        new ArrayList<>(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

    Authentication newAuth = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
        authentication.getCredentials(), updatedAuthorities);
    sc.setAuthentication(newAuth);

    // TODO touch account, i.e. log the successful verification

    authenticationSuccessEvent(newAuth);

    return "redirect:/dashboard";
  }

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @RequestMapping(method = RequestMethod.POST, path = VERIFY_RECOVERY_CODE_URL)
  public String verifyRecoveryCode(@ModelAttribute @Valid RecoveryCodeDTO recoveryCode,
      BindingResult validationResult, Authentication authentication,
      RedirectAttributes redirectAttributes) {
    if (validationResult.hasErrors()) {
      MultiFactorAuthenticationError error =
          new MultiFactorAuthenticationError("Bad recovery code");
      authenticationFailureEvent(error, authentication);
      redirectAttributes.addAttribute("error", "failure");
      return "redirect:/iam/verify";
    }

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new MultiFactorAuthenticationError("Account not found"));

    Set<IamTotpRecoveryCode> accountRecoveryCodes = account.getTotpMfa().getRecoveryCodes();
    if (!isValidRecoveryCode(accountRecoveryCodes, recoveryCode.getRecoveryCode())) {
      MultiFactorAuthenticationError error =
          new MultiFactorAuthenticationError("Bad recovery code");
      authenticationFailureEvent(error, authentication);
      redirectAttributes.addAttribute("error", "failure");
      return "redirect:/iam/verify";
    }

    SecurityContext sc = SecurityContextHolder.getContext();
    List<GrantedAuthority> updatedAuthorities =
        new ArrayList<>(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

    Authentication newAuth = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
        authentication.getCredentials(), updatedAuthorities);
    sc.setAuthentication(newAuth);

    // TODO touch account, i.e. log the successful verification

    authenticationSuccessEvent(newAuth);

    return "redirect:/iam/authenticator-app/recovery-code/reset";
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(MultiFactorAuthenticationError.class)
  @ResponseBody
  public ErrorDTO handleMultiFactorAuthenticationError(MultiFactorAuthenticationError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  private boolean isValidRecoveryCode(Set<IamTotpRecoveryCode> accountRecoveryCodes,
      String inputRecoveryCode) {
    for (IamTotpRecoveryCode recoveryCodeObject : accountRecoveryCodes) {
      String currentRecoveryCode = recoveryCodeObject.getCode();
      if (currentRecoveryCode.equals(inputRecoveryCode)) {
        return true;
      }
    }

    return false;
  }
}
