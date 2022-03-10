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

import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.BadMfaCodeError;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Controller for customising user's authenticator app MFA settings Can enable or disable the
 * feature through POST requests to the relevant endpoints
 */
@SuppressWarnings("deprecation")
@Controller
public class AuthenticatorAppSettingsController {

  public static final String BASE_URL = "/iam/authenticator-app";
  public static final String ADD_SECRET_URL = BASE_URL + "/add-secret";
  public static final String ENABLE_URL = BASE_URL + "/enable";
  public static final String DISABLE_URL = BASE_URL + "/disable";

  private final IamTotpMfaService service;
  private final IamAccountRepository accountRepository;
  private final QrGenerator qrGenerator;

  @Autowired
  public AuthenticatorAppSettingsController(IamTotpMfaService service,
      IamAccountRepository accountRepository, QrGenerator qrGenerator) {
    this.service = service;
    this.accountRepository = accountRepository;
    this.qrGenerator = qrGenerator;
  }


  /**
   * Before we can enable authenticator app, we must first add a TOTP secret to the user's account
   * The secret is not active until the user enables authenticator app at the /enable endpoint
   * 
   * @return DTO containing the plaintext TOTP secret and QR code URI for scanning
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = ADD_SECRET_URL, method = RequestMethod.PUT,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public SecretAndDataUriDTO addSecret() {
    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    IamTotpMfa totpMfa = service.addTotpMfaSecret(account);
    SecretAndDataUriDTO dto = new SecretAndDataUriDTO(totpMfa.getSecret());

    try {
      String dataUri = generateQRCodeFromSecret(totpMfa.getSecret(), account.getUsername());
      dto.setDataUri(dataUri);
    } catch (QrGenerationException e) {
      throw new BadMfaCodeError("Could not generate QR code");
    }

    return dto;
  }


  /**
   * Enable authenticator app MFA on account User sends a TOTP through POST which we verify before
   * enabling
   * 
   * @param code the TOTP to verify
   * @param validationResult result of validation checks on the code
   * @return nothing
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = ENABLE_URL, method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void enableAuthenticatorApp(@ModelAttribute @Valid TotpDTO code,
      BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new BadMfaCodeError("Bad code");
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    boolean valid = false;

    try {
      valid = service.verifyTotp(account, code.getCode());
    } catch (MfaSecretNotFoundException e) {
      throw e;
    }

    if (!valid) {
      throw new BadMfaCodeError("Bad code");
    }

    service.enableTotpMfa(account);
  }


  /**
   * Disable authenticator app MFA on account User sends a TOTP through POST which we verify before
   * disabling
   * 
   * @param code the TOTP to verify
   * @param validationResult result of validation checks on the code
   * @return nothing
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = DISABLE_URL, method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void disableAuthenticatorApp(@Valid TotpDTO code, BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new BadMfaCodeError("Bad code");
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    boolean valid = false;

    try {
      valid = service.verifyTotp(account, code.getCode());
    } catch (MfaSecretNotFoundException e) {
      throw e;
    }

    if (!valid) {
      throw new BadMfaCodeError("Bad code");
    }

    service.disableTotpMfa(account);
  }

  /**
   * Fetch and return the logged-in username from security context
   * 
   * @return String username
   */
  private String getUsernameFromSecurityContext() {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof OAuth2Authentication) {
      OAuth2Authentication oauth = (OAuth2Authentication) auth;
      auth = oauth.getUserAuthentication();
    }
    return auth.getName();
  }


  /**
   * Constructs a data URI for displaying a QR code of the TOTP secret for the user to scan Takes in
   * details about the issuer, length of TOTP and period of expiry from application properties
   * 
   * @param secret the TOTP secret
   * @param username the logged-in user (attaches a username to the secret in the authenticator app)
   * @return the data URI to be used with an <img> tag
   * @throws QrGenerationException
   */
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


  /**
   * Exception handler for when an TOTP secret is unexpectedly missing
   * 
   * @param e MfaSecretNotFoundException
   * @return DTO containing error details
   */
  @ResponseStatus(code = HttpStatus.CONFLICT)
  @ExceptionHandler(MfaSecretNotFoundException.class)
  @ResponseBody
  public ErrorDTO handleMfaSecretNotFoundException(MfaSecretNotFoundException e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  /**
   * Exception handler for when an TOTP secret is unexpectedly found
   * 
   * @param e MfaSecretAlreadyBoundException
   * @return DTO containing error details
   */
  @ResponseStatus(code = HttpStatus.CONFLICT)
  @ExceptionHandler(MfaSecretAlreadyBoundException.class)
  @ResponseBody
  public ErrorDTO handleMfaSecretAlreadyBoundException(MfaSecretAlreadyBoundException e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  /**
   * Exception handler for when authenticator app MFA is unexpectedly enabled already
   * 
   * @param e TotpMfaAlreadyEnabledException
   * @return DTO containing error details
   */
  @ResponseStatus(code = HttpStatus.CONFLICT)
  @ExceptionHandler(TotpMfaAlreadyEnabledException.class)
  @ResponseBody
  public ErrorDTO handleTotpMfaAlreadyEnabledException(TotpMfaAlreadyEnabledException e) {
    return ErrorDTO.fromString(e.getMessage());
  }


  /**
   * Exception handler for when a received TOTP is invalid
   * 
   * @param e BadCodeError
   * @return DTO containing error details
   */
  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(BadMfaCodeError.class)
  @ResponseBody
  public ErrorDTO handleBadCodeError(BadMfaCodeError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
