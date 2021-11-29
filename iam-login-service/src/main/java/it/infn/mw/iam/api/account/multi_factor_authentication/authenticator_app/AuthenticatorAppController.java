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
package it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app;

import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.BadCodeError;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.api.scim.controller.utils.ValidationErrorMessageHelper;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import org.springframework.stereotype.Controller;

@SuppressWarnings("deprecation")
@Controller
@RequestMapping("/iam/authenticator-app")
public class AuthenticatorAppController {

  final IamAccountService service;
  final IamAccountRepository accountRepository;

  @Autowired
  public AuthenticatorAppController(IamAccountService service,
      IamAccountRepository accountRepository) {
    this.service = service;
    this.accountRepository = accountRepository;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/add-secret", method = RequestMethod.GET,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public SecretAndDataUriDTO addSecret() {
    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    account = service.addTotpMfaSecret(account);

    SecretAndDataUriDTO dto = new SecretAndDataUriDTO(account.getTotpMfa().getSecret());
    try {
      String dataUri =
          generateQRCodeFromSecret(account.getTotpMfa().getSecret(), account.getUsername());
      dto.setDataUri(dataUri);
    } catch (QrGenerationException e) {
      // TODO Auto-generated catch block
    }
    return dto;
  }

  // TODO switch to this post method from get request, post method not currently working
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/enable", method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void enableAuthenticatorApp(@Valid CodeDTO code, BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new BadCodeError(
          ValidationErrorMessageHelper.buildValidationErrorMessage("Bad code", validationResult));
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    // TODO checks to see if provided code valid

    service.enableTotpMfa(account);
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/disable", method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void disableAuthenticatorApp(@Valid CodeDTO code, BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new BadCodeError(
          ValidationErrorMessageHelper.buildValidationErrorMessage("Bad code", validationResult));
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    // TODO checks to see if provided code valid

    service.disableTotpMfa(account);
  }

  private String getUsernameFromSecurityContext() {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof OAuth2Authentication) {
      OAuth2Authentication oauth = (OAuth2Authentication) auth;
      auth = oauth.getUserAuthentication();
    }
    return auth.getName();
  }

  private String generateQRCodeFromSecret(String secret, String username)
      throws QrGenerationException {

    // TODO add in admin configuration through properties file
    QrData data = new QrData.Builder().label(username)
      .secret(secret)
      .issuer("IAM Test")
      .algorithm(HashingAlgorithm.SHA1)
      .digits(6)
      .period(30)
      .build();

    byte[] imageData;

    // TODO autowire this
    QrGenerator qrGenerator = new ZxingPngQrGenerator();

    try {
      imageData = qrGenerator.generate(data);
    } catch (QrGenerationException e) {
      throw e;
    }

    String mimeType = qrGenerator.getImageMimeType();
    return getDataUriForImage(imageData, mimeType);
  }

  @ResponseStatus(code = HttpStatus.CONFLICT)
  @ExceptionHandler(MfaSecretAlreadyBoundException.class)
  @ResponseBody
  public ErrorDTO handlemfaSecretAlreadyBoundException(MfaSecretAlreadyBoundException e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
