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

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.IncorrectCodeError;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.InvalidCodeError;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
@Controller
public class AuthenticatorAppController {

  public static final String BASE_URL = "/iam/authenticator-app";
  public static final String ADD_SECRET_URL = BASE_URL + "/add-secret";
  public static final String ENABLE_URL = BASE_URL + "/enable";
  public static final String DISABLE_URL = BASE_URL + "/disable";

  final IamAccountService service;
  final IamAccountRepository accountRepository;
  private QrGenerator qrGenerator;
  private CodeVerifier codeVerifier;

  @Autowired
  public AuthenticatorAppController(IamAccountService service,
      IamAccountRepository accountRepository, QrGenerator qrGenerator, CodeVerifier codeVerifier) {
    this.service = service;
    this.accountRepository = accountRepository;
    this.qrGenerator = qrGenerator;
    this.codeVerifier = codeVerifier;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = ADD_SECRET_URL, method = RequestMethod.PUT,
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
      // TODO QR code couldn't be generated. What should be done here?
    }
    return dto;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = ENABLE_URL, method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void enableAuthenticatorApp(@ModelAttribute @Valid CodeDTO code,
      BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new InvalidCodeError("Invalid code format. Code must be six numeric characters");
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    if (!codeVerifier.isValidCode(account.getTotpMfa().getSecret(), code.getCode())) {
      throw new IncorrectCodeError("Incorrect code. Try again");
    }

    service.enableTotpMfa(account);
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = DISABLE_URL, method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void disableAuthenticatorApp(@Valid CodeDTO code, BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new InvalidCodeError("Invalid code format. Code must be six numeric characters");
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    if (!codeVerifier.isValidCode(account.getTotpMfa().getSecret(), code.getCode())) {
      throw new IncorrectCodeError("Incorrect code. Try again");
    }

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
  public ErrorDTO handleMfaSecretAlreadyBoundException(MfaSecretAlreadyBoundException e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidCodeError.class)
  @ResponseBody
  public ErrorDTO handleInvalidCodeError(InvalidCodeError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(IncorrectCodeError.class)
  @ResponseBody
  public ErrorDTO handleIncorrectCodeError(IncorrectCodeError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
