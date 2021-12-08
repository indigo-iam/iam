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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

//TODO when unauthenticated and navigating to other pages like /dashboard, we redirect to /login. But here we show up as unauthorized. Can we replicate the behaviour of /dashboard?

@Controller
public class MfaVerifyController {

  private final AccountUtils accountUtils;
  private final CodeVerifier codeVerifier;
  private final AuthenticationEventPublisher eventPublisher;

  // TODO - step up authentication page can't read SPRING_SECURITY_LAST_EXCEPTION.message to display
  // "Bad code" error. Fix this and use
  // ExternalAuthenticationHandlerSupport.saveAuthenticationErrorInSession() as a reference

  @Autowired
  public MfaVerifyController(AccountUtils accountUtils, CodeVerifier codeVerifier,
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
  @RequestMapping(method = RequestMethod.GET, path = "/iam/verify2fa")
  public String getVerify2faView() {
    return "iam/verify-mfa";
  }

  // TODO separate this into a different path. Currently spring complains about a lack of an
  // authentication object in security context
  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @RequestMapping(method = RequestMethod.POST, path = "/iam/verify2fa")
  public String verify2fa(@ModelAttribute @Valid CodeDTO code, BindingResult validationResult,
      Authentication authentication, RedirectAttributes redirectAttributes) {
    if (validationResult.hasErrors()) {
      MultiFactorAuthenticationError error = new MultiFactorAuthenticationError("Bad MFA code");
      authenticationFailureEvent(error, authentication);
      redirectAttributes.addAttribute("error", "failure");
      return "redirect:/iam/verify2fa";
    }

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new MultiFactorAuthenticationError("Account not found"));

    if (!codeVerifier.isValidCode(account.getTotpMfa().getSecret(), code.getCode())) {
      MultiFactorAuthenticationError error = new MultiFactorAuthenticationError("Bad MFA code");
      authenticationFailureEvent(error, authentication);
      redirectAttributes.addAttribute("error", "failure");
      return "redirect:/iam/verify2fa";
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

  /**
   * Exception handler for an incorrect or invalid code or a logged-in account not being found
   * 
   * @param e MultiFactorAuthenticationError
   * @return DTO containing error details
   */
  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(MultiFactorAuthenticationError.class)
  @ResponseBody
  public ErrorDTO handleMultiFactorAuthenticationError(MultiFactorAuthenticationError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
