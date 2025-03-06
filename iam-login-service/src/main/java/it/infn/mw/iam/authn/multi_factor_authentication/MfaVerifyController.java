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
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorSettingsDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

/**
 * Presents the step-up authentication page for verifying identity after successful username +
 * password authentication. Only accessible if the user is pre-authenticated, i.e. has authenticated
 * with username + password but not fully authenticated yet
 */
@Controller
@RequestMapping(MFA_VERIFY_URL)
public class MfaVerifyController {

  public static final String MFA_VERIFY_URL = "/iam/verify";
  final IamAccountRepository accountRepository;
  final IamTotpMfaRepository totpMfaRepository;

  public MfaVerifyController(IamAccountRepository accountRepository,
      IamTotpMfaRepository totpMfaRepository) {
    this.accountRepository = accountRepository;
    this.totpMfaRepository = totpMfaRepository;
  }

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @GetMapping("")
  public String getVerifyMfaView(Authentication authentication, ModelMap model) {
    IamAccount account = accountRepository.findByUsername(authentication.getName())
      .orElseThrow(() -> NoSuchAccountError.forUsername(authentication.getName()));
    MultiFactorSettingsDTO dto = populateMfaSettings(account);
    model.addAttribute("factors", dto.toJson());
    
    if (authentication instanceof PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken) {
      setAuthentication(preAuthenticatedAuthenticationToken);
    }
    return "iam/verify-mfa";
  }

  private void setAuthentication(PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken) {
    Set<GrantedAuthority> authenticatedAuthorities = new HashSet<>(
        preAuthenticatedAuthenticationToken.getAuthorities());
    if (preAuthenticatedAuthenticationToken.getPrincipal() instanceof User) {
      User user = (User) preAuthenticatedAuthenticationToken.getPrincipal();

      ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(user.getUsername(), "SECRET",
          authenticatedAuthorities);
      token.setAuthenticated(false);
      token.setAuthenticationMethodReferences(Set.of(
          new IamAuthenticationMethodReference(X509.getValue())));
      token.setPreAuthenticated(true);
      SecurityContextHolder.getContext().setAuthentication(token);
    }
  }

  /**
   * Populates a DTO containing info on which additional factors of authentication are active
   * 
   * @param account the MFA-enabled account
   * @return DTO with populated settings
   */
  private MultiFactorSettingsDTO populateMfaSettings(IamAccount account) {
    MultiFactorSettingsDTO dto = new MultiFactorSettingsDTO();

    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (totpMfaOptional.isPresent()) {
      IamTotpMfa totpMfa = totpMfaOptional.get();
      dto.setAuthenticatorAppActive(totpMfa.isActive());
    } else {
      dto.setAuthenticatorAppActive(false);
    }

    return dto;
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(NoSuchAccountError.class)
  @ResponseBody
  public ErrorDTO handleNoSuchAccountError(NoSuchAccountError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
