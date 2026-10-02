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

import java.time.Clock;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.BadMfaCodeError;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorTotpCheckProvider;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.oidc.AuthenticationTimeStamper;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.core.util.IamAuthenticationLogger;
import it.infn.mw.iam.core.web.aup.EnforceAupFilter;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

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
  public static final String DISABLE_URL_FOR_ACCOUNT_ID = BASE_URL + "/reset/{accountId}";
  public static final String BAD_CODE = "Bad TOTP";
  public static final String CODE_GENERATION_ERROR = "Could not generate QR code";
  public static final String MFA_SECRET_NOT_FOUND_MESSAGE =
      "No multi-factor secret is attached to this account";
  public static final String REQUESTING_MFA = "iam.mfa.requesting-mfa";    

  private final IamTotpMfaService service;
  private final IamAccountRepository accountRepository;
  private final IamTotpMfaProperties iamTotpMfaProperties;
  private final NotificationFactory notificationFactory;
  private final AUPSignatureCheckService aupSignatureCheckService;
  private final ApplicationEventPublisher eventPublisher;
  private final AccountUtils accountUtils;
  private final Clock clock;
  private final RequestCache requestCache = new HttpSessionRequestCache();

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  public AuthenticatorAppSettingsController(IamTotpMfaService service,
      IamAccountRepository accountRepository, IamTotpMfaProperties iamTotpMfaProperties,
      NotificationFactory notificationFactory, AUPSignatureCheckService aupSignatureCheckService,
      ApplicationEventPublisher eventPublisher, AccountUtils accountUtils, Clock clock) {
    this.service = service;
    this.accountRepository = accountRepository;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
    this.notificationFactory = notificationFactory;
    this.aupSignatureCheckService = aupSignatureCheckService;
    this.eventPublisher = eventPublisher;
    this.accountUtils = accountUtils;
    this.clock = clock;
  }

  /**
   * Before we can enable authenticator app, we must first add a TOTP secret to the user's account
   * The secret is not active until the user enables authenticator app at the /enable endpoint
   * 
   * @return DTO containing the plaintext TOTP secret and QR code URI for scanning
   */
  @PreAuthorize("hasAnyRole('USER', 'PRE_AUTHENTICATED')")
  @PutMapping(value = ADD_SECRET_URL, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public SecretAndDataUriDTO addSecret() throws IamTotpMfaInvalidArgumentError {
    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    IamTotpMfa totpMfa = service.addTotpMfaSecret(account);
    String mfaSecret = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(totpMfa.getSecret(),
        iamTotpMfaProperties.getPasswordToEncryptAndDecrypt());

    try {
      SecretAndDataUriDTO dto = new SecretAndDataUriDTO(mfaSecret);

      String dataUri = service.generateQRCodeFromSecret(mfaSecret, account.getUsername());
      dto.setDataUri(dataUri);

      return dto;
    } catch (QrGenerationException e) {
      throw new BadMfaCodeError(CODE_GENERATION_ERROR);
    }
  }

  /**
   * Enable authenticator app MFA on account User sends a TOTP through POST which we verify before
   * enabling
   * 
   * @param code the TOTP to verify
   * @param validationResult result of validation checks on the code
   * @return where the client should navigate next &mdash; the request that brought the user to
   *         enrollment in the first place, if one is still saved, rather than IAM's own dashboard
   */
  @PreAuthorize("hasAnyRole('USER', 'PRE_AUTHENTICATED')")
  @PostMapping(value = ENABLE_URL, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public EnableMfaResponseDTO enableAuthenticatorApp(@ModelAttribute @Valid CodeDTO code,
      BindingResult validationResult, HttpSession session, HttpServletRequest request,
      HttpServletResponse response) {
    if (validationResult.hasErrors()) {
      throw new BadMfaCodeError(BAD_CODE);
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    boolean valid = false;

    try {
      valid = service.verifyTotp(account, code.getCode());
    } catch (MfaSecretNotFoundException e) {
      throw new MfaSecretNotFoundException(MFA_SECRET_NOT_FOUND_MESSAGE);
    }

    if (!valid) {
      throw new BadMfaCodeError(BAD_CODE);
    }

    service.enableTotpMfa(account);
    notificationFactory.createMfaEnableMessage(account);
    session.removeAttribute(REQUESTING_MFA);

    Authentication current = SecurityContextHolder.getContext().getAuthentication();

    if (isPendingMfaAuthentication(current)) {
      String aupRedirect = upgradeSessionAfterEnrollment(current, session, account);
      return new EnableMfaResponseDTO(
          aupRedirect != null ? aupRedirect : resolvePostEnableRedirectUrl(request, response));
    }

    if (accountUtils.isPreAuthenticated(current)) {
      // Still PRE_AUTHENTICATED, but missing what upgradeToFullyAuthenticated needs to do it
      // safely (e.g. the X.509 pre-auth token MfaVerifyController builds carries no
      // fullyAuthenticatedAuthorities). Resuming the saved request now would hand it to a
      // principal that isn't fully authenticated yet -- the same bug this fix started from, just
      // for a different token shape. /iam/verify is the one path that's always safe here.
      return new EnableMfaResponseDTO(MfaVerifyController.MFA_VERIFY_URL);
    }

    // Already fully authenticated (voluntary enrollment from the dashboard) or a token type
    // this enrollment flow doesn't drive (OAuth2): nothing to upgrade.
    return new EnableMfaResponseDTO(resolvePostEnableRedirectUrl(request, response));
  }

  /**
   * True if {@code authentication} is a session still waiting to clear MFA enrollment with enough
   * information to upgrade in place, i.e. the one case
   * {@link MultiFactorTotpCheckProvider#upgradeToFullyAuthenticated} knows how to handle.
   *
   * <p>
   * Deliberately not based on {@code authentication.isAuthenticated()}: {@code ExtendedAuthenticationToken}
   * marks itself unauthenticated while PRE_AUTHENTICATED, but the external-IdP tokens
   * ({@code AbstractExternalAuthenticationToken} subclasses built by e.g. {@code OIDCAuthenticationProvider})
   * are built from an authorities-taking constructor that marks them authenticated even though they
   * only hold {@code ROLE_PRE_AUTHENTICATED}. {@link AccountUtils#isAuthenticated} special-cases
   * {@code ExtendedAuthenticationToken} for exactly this reason; the role check below is what
   * actually tells PRE_AUTHENTICATED apart from either kind of token here.
   */
  private boolean isPendingMfaAuthentication(Authentication authentication) {
    if (!accountUtils.isPreAuthenticated(authentication)) {
      return false;
    }
    if (authentication instanceof ExtendedAuthenticationToken token) {
      return token.getFullyAuthenticatedAuthorities() != null;
    }
    if (authentication instanceof AbstractExternalAuthenticationToken<?> token) {
      return token.getFullyAuthenticatedAuthorities() != null;
    }
    return false;
  }

  /**
   * Finishes what {@code /iam/verify} would otherwise do for this user: upgrade the session to
   * full authentication (the TOTP code was already proved above, so there is no need to ask for it
   * again) and run the same bookkeeping {@link it.infn.mw.iam.authn.EnforceAupSignatureSuccessHandler}
   * runs on every other login &mdash; the auth timestamp, the last-login time, the audit event, and
   * the AUP signature check.
   *
   * @return the AUP signing page, if the account still needs to sign it; {@code null} otherwise
   */
  private String upgradeSessionAfterEnrollment(Authentication current, HttpSession session,
      IamAccount account) {

    Authentication upgraded = MultiFactorTotpCheckProvider.upgradeToFullyAuthenticated(current);
    SecurityContextHolder.getContext().setAuthentication(upgraded);
    session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);

    session.setAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP, Date.from(clock.instant()));
    IamAuthenticationLogger.INSTANCE.logAuthenticationSuccess(upgraded);
    accountRepository.touchLastLoginTimeForUserWithUsername(account.getUsername());
    eventPublisher.publishEvent(
        new InteractiveAuthenticationSuccessEvent(upgraded, AuthenticatorAppSettingsController.class));

    if (aupSignatureCheckService.needsAupSignature(account)) {
      session.setAttribute(EnforceAupFilter.REQUESTING_SIGNATURE, true);
      return EnforceAupFilter.AUP_SIGN_PATH;
    }

    return null;
  }

  /**
   * Works out where to send the user once authenticator app MFA is enabled.
   *
   * <p>
   * Whatever request brought the user to the enrollment page in the first place &mdash; typically
   * an OAuth2 {@code /authorize} call from a client application &mdash; is still sitting untouched
   * in the session's {@link RequestCache}, so resume it directly, the same way
   * {@link RootIsDashboardSuccessHandler} does for a returning user who verifies an existing TOTP
   * code.
   */
  private String resolvePostEnableRedirectUrl(HttpServletRequest request,
      HttpServletResponse response) {
    SavedRequest savedRequest = requestCache.getRequest(request, response);
    if (savedRequest == null) {
      return RootIsDashboardSuccessHandler.DASHBOARD_URL;
    }

    String redirectUrl = savedRequest.getRedirectUrl();
    if (RootIsDashboardSuccessHandler.redirectsToIamRoot(redirectUrl, iamBaseUrl)) {
      requestCache.removeRequest(request, response);
      return RootIsDashboardSuccessHandler.DASHBOARD_URL;
    }

    return redirectUrl;
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
  @PostMapping(value = DISABLE_URL, produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void disableAuthenticatorApp(@Valid CodeDTO code, BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new BadMfaCodeError(BAD_CODE);
    }

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    boolean valid = false;

    try {
      valid = service.verifyTotp(account, code.getCode());
    } catch (MfaSecretNotFoundException e) {
      throw new MfaSecretNotFoundException(MFA_SECRET_NOT_FOUND_MESSAGE);
    }

    if (!valid) {
      throw new BadMfaCodeError(BAD_CODE);
    }

    service.disableTotpMfa(account);
    notificationFactory.createMfaDisableMessage(account);
  }

  /**
   * Reset authenticator app MFA on account by Admin on request
   * 
   * @param accountId the accountId to get user account
   * @return nothing
   */
  @PreAuthorize("hasRole('ADMIN')")
  @DeleteMapping(value = DISABLE_URL_FOR_ACCOUNT_ID, produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void disableAuthenticatorAppForAccount(@PathVariable String accountId) {
    IamAccount account = accountRepository.findByUuid(accountId)
      .orElseThrow(() -> NoSuchAccountError.forUuid(accountId));
    service.disableTotpMfa(account);
    notificationFactory.createMfaDisableMessage(account);
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
