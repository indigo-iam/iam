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
package it.infn.mw.iam.api.aup;

import static java.lang.String.format;

import java.util.Date;
import java.util.Optional;
import java.util.function.Supplier;

import javax.security.auth.login.AccountNotFoundException;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.error.AupNotFoundError;
import it.infn.mw.iam.api.aup.error.AupSignatureNotFoundError;
import it.infn.mw.iam.api.aup.model.AupSignatureConverter;
import it.infn.mw.iam.api.aup.model.AupSignatureDTO;
import it.infn.mw.iam.api.aup.model.AupSignaturePatchRequestDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.audit.events.aup.AupSignatureDeletedEvent;
import it.infn.mw.iam.audit.events.aup.AupSignedEvent;
import it.infn.mw.iam.audit.events.aup.AupSignedOnBehalfEvent;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureUpdateError;

@SuppressWarnings("deprecation")
@RestController
@Transactional
public class AupSignatureController {

  private static final String ACCOUNT_NOT_FOUND_FOR_ID_MESSAGE = "Account not found for id: %s";
  private static final String ACCOUNT_NOT_FOUND_FOR_AUTHENTICATED_USER_MESSAGE =
      "Account not found for authenticated user";

  private final AupSignatureConverter signatureConverter;
  private final AccountUtils accountUtils;
  private final IamAupSignatureRepository signatureRepo;
  private final IamAupRepository aupRepo;
  private final TimeProvider timeProvider;
  private final ApplicationEventPublisher eventPublisher;
  private final NotificationFactory notificationFactory;

  public AupSignatureController(AupSignatureConverter conv, AccountUtils utils,
      IamAupSignatureRepository signatureRepo, IamAupRepository aupRepo, TimeProvider timeProvider,
      ApplicationEventPublisher publisher, NotificationFactory notificationFactory) {
    this.signatureConverter = conv;
    this.accountUtils = utils;
    this.signatureRepo = signatureRepo;
    this.aupRepo = aupRepo;
    this.timeProvider = timeProvider;
    this.eventPublisher = publisher;
    this.notificationFactory = notificationFactory;
  }

  private Supplier<AupNotFoundError> aupNotFoundException() {
    return AupNotFoundError::new;
  }

  private Supplier<AccountNotFoundException> accountNotFoundException(String message) {
    return () -> new AccountNotFoundException(message);
  }

  private Supplier<AupSignatureNotFoundError> signatureNotFound(IamAccount account) {
    return () -> new AupSignatureNotFoundError(account);
  }

  @PostMapping(value = "/iam/aup/signature")
  @PreAuthorize("hasRole('ROLE_USER')")
  @ResponseStatus(code = HttpStatus.CREATED)
  public void signAup() throws AccountNotFoundException {

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(accountNotFoundException(ACCOUNT_NOT_FOUND_FOR_AUTHENTICATED_USER_MESSAGE));

    Date now = new Date(timeProvider.currentTimeMillis());
    IamAupSignature signature = signatureRepo.createSignatureForAccount(aup, account, now);
    eventPublisher.publishEvent(new AupSignedEvent(this, signature));
  }

  @GetMapping(value = "/iam/aup/signature")
  @PreAuthorize("hasRole('ROLE_USER')")
  public AupSignatureDTO getSignature() throws AccountNotFoundException {

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(accountNotFoundException(ACCOUNT_NOT_FOUND_FOR_AUTHENTICATED_USER_MESSAGE));

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());
    IamAupSignature sig =
        signatureRepo.findSignatureForAccount(aup, account).orElseThrow(signatureNotFound(account));
    return signatureConverter.dtoFromEntity(sig);
  }

  @GetMapping(value = "/iam/aup/signature/{accountId}")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_GM', 'ROLE_READER') or #iam.isUser(#accountId)")
  public AupSignatureDTO getSignatureForAccount(@PathVariable String accountId)
      throws AccountNotFoundException {

    IamAccount account = accountUtils.getByAccountId(accountId)
      .orElseThrow(accountNotFoundException(format(ACCOUNT_NOT_FOUND_FOR_ID_MESSAGE, accountId)));

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());
    IamAupSignature sig =
        signatureRepo.findSignatureForAccount(aup, account).orElseThrow(signatureNotFound(account));

    return signatureConverter.dtoFromEntity(sig);
  }

  @PatchMapping(value = "/iam/aup/signature/{accountId}")
  @ResponseStatus(value = HttpStatus.CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public AupSignatureDTO updateSignatureForAccount(@PathVariable String accountId,
      @RequestBody(required = false) @Validated AupSignaturePatchRequestDTO dto,
      Authentication authentication) throws AccountNotFoundException, IamAupSignatureUpdateError {

    Optional<IamAccount> updaterAccount = accountUtils.getAuthenticatedUserAccount();

    IamAccount account = accountUtils.getByAccountId(accountId)
      .orElseThrow(accountNotFoundException(format(ACCOUNT_NOT_FOUND_FOR_ID_MESSAGE, accountId)));
    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());

    Date signatureTime =
        dto == null ? new Date(timeProvider.currentTimeMillis()) : dto.getSignatureTime();
    IamAupSignature signature =
        signatureRepo.createSignatureForAccount(aup, account, signatureTime);

    String principal = null;

    if (updaterAccount.isPresent()) {
      principal = updaterAccount.get().getUsername();
      eventPublisher.publishEvent(AupSignedOnBehalfEvent.signedByUser(this, principal, signature));
    } else if (authentication instanceof OAuth2Authentication) {
      OAuth2Authentication oauth2Auth = (OAuth2Authentication) authentication;
      principal = oauth2Auth.getOAuth2Request().getClientId();
      eventPublisher
        .publishEvent(AupSignedOnBehalfEvent.signedByClient(this, principal, signature));
    }

    return signatureConverter.dtoFromEntity(signature);
  }

  @DeleteMapping(value = "/iam/aup/signature/{accountId}")
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void deleteSignatureForAccount(@PathVariable String accountId,
      Authentication authentication) throws AccountNotFoundException, IamAupSignatureUpdateError {

    Optional<IamAccount> deleterAccount = accountUtils.getAuthenticatedUserAccount();
    IamAccount signatureAccount = accountUtils.getByAccountId(accountId)
      .orElseThrow(accountNotFoundException(format(ACCOUNT_NOT_FOUND_FOR_ID_MESSAGE, accountId)));

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());

    Optional<IamAupSignature> signature =
        signatureRepo.findSignatureForAccount(aup, signatureAccount);

    if (signature.isPresent()) {
      signatureRepo.deleteSignatureForAccount(aup, signatureAccount);

      String principal = null;

      if (deleterAccount.isPresent()) {
        principal = deleterAccount.get().getUsername();
        eventPublisher
          .publishEvent(AupSignatureDeletedEvent.deletedByUser(this, principal, signature.get()));
      } else if (authentication instanceof OAuth2Authentication) {
        OAuth2Authentication oauth2Auth = (OAuth2Authentication) authentication;
        principal = oauth2Auth.getOAuth2Request().getClientId();
        eventPublisher
          .publishEvent(AupSignatureDeletedEvent.deletedByClient(this, principal, signature.get()));
      }
      notificationFactory.createAupSignatureRequestMessage(signatureAccount);
    }
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(AupSignatureNotFoundError.class)
  public ErrorDTO notFoundError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(AccountNotFoundException.class)
  public ErrorDTO accountNotFoundError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(AupNotFoundError.class)
  public ErrorDTO aupNotFoundError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.METHOD_NOT_ALLOWED)
  @ExceptionHandler(IamAupSignatureUpdateError.class)
  public ErrorDTO aupSignatureUpdateError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
