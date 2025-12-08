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
import java.util.Set;

import org.springframework.http.HttpStatus;
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

import dev.samstevens.totp.exceptions.QrGenerationException;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.BadMfaCodeError;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

/**
 * Presents the step-up authentication page for verifying identity after successful username +
 * password authentication. Only accessible if the user is pre-authenticated, i.e. has authenticated
 * with username + password but not fully authenticated yet
 */
@Controller
public class MfaVerifyController {

  public static final String MFA_VERIFY_URL = "/iam/verify";
  final IamAccountRepository accountRepository;
  final IamTotpMfaRepository totpMfaRepository;
  private final AccountUtils accountUtils;
  private final IamTotpMfaService iamTotpMfaService;
  private final IamTotpMfaProperties iamTotpMfaProperties;

  public MfaVerifyController(IamAccountRepository accountRepository,
      IamTotpMfaRepository totpMfaRepository, AccountUtils accountUtils, 
      IamTotpMfaService iamTotpMfaService, IamTotpMfaProperties iamTotpMfaProperties) {
    this.accountRepository = accountRepository;
    this.totpMfaRepository = totpMfaRepository;
    this.accountUtils = accountUtils;
    this.iamTotpMfaService = iamTotpMfaService;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
  }

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @GetMapping(value = MFA_VERIFY_URL)
  public String getVerifyMfaView(Authentication authentication, ModelMap model) {
    IamAccount account = accountRepository.findByUsername(authentication.getName())
      .orElseThrow(() -> NoSuchAccountError.forUsername(authentication.getName()));
    model.addAttribute("isAuthenticatorAppActive", isAuthenticatorAppActive(account));

    if (authentication instanceof PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken) {
      setAuthentication(preAuthenticatedAuthenticationToken);
    }
    return "iam/verify-mfa";
  }

  private boolean isAuthenticatorAppActive(IamAccount account) {
    return totpMfaRepository.findByAccount(account).map(IamTotpMfa::isActive).orElse(false);
  }

  private void setAuthentication(PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken) {
    Set<GrantedAuthority> authenticatedAuthorities = new HashSet<>(
        preAuthenticatedAuthenticationToken.getAuthorities());
    if (preAuthenticatedAuthenticationToken.getPrincipal() instanceof User user) {
      ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(user.getUsername(), "SECRET",
          authenticatedAuthorities);
      token.setAuthenticated(false);
      token.setAuthenticationMethodReferences(Set.of(
          new IamAuthenticationMethodReference(X509.getValue())));
      token.setPreAuthenticated(true);
      SecurityContextHolder.getContext().setAuthentication(token);
    }
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping(value = "/iam/mfa/acivate")
  public String getActivateMfaView(Authentication authentication, ModelMap model) {
    String dataUri = "";
    final String username = accountUtils.getAuthenticatedUserAccount().get().getUsername();
    //final String username = ((User)authentication.getPrincipal()).getUsername();

    IamAccount account = accountRepository.findByUsername(username)
        .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    IamTotpMfa totpMfa = iamTotpMfaService.addTotpMfaSecret(account);
    String mfaSecret = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(totpMfa.getSecret(),
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt());

    try {
      dataUri = iamTotpMfaService.generateQRCodeFromSecret(mfaSecret, account.getUsername());
    } catch (QrGenerationException e) {
      throw new BadMfaCodeError("Could not generate QR code");
    }

    model.addAttribute("mfaSecret", mfaSecret);
    model.addAttribute("dataUri", dataUri);
    model.addAttribute("codeMinlength", 6);

    if (authentication instanceof PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken) {
      setAuthentication(preAuthenticatedAuthenticationToken);
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
