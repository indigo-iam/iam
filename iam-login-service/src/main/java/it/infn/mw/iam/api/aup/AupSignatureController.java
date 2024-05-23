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

import java.util.Date;
import java.util.function.Supplier;

import javax.security.auth.login.AccountNotFoundException;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.error.AupNotFoundError;
import it.infn.mw.iam.api.aup.error.AupSignatureNotFoundError;
import it.infn.mw.iam.api.aup.model.AupSignatureConverter;
import it.infn.mw.iam.api.aup.model.AupSignatureDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.audit.events.aup.AupSignatureDeletedEvent;
import it.infn.mw.iam.audit.events.aup.AupSignedEvent;
import it.infn.mw.iam.audit.events.aup.AupSignedOnBehalfEvent;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;

@RestController
@Transactional
public class AupSignatureController {

  private final AupSignatureConverter signatureConverter;
  private final AccountUtils accountUtils;
  private final IamAupSignatureRepository signatureRepo;
  private final IamAupRepository aupRepo;
  private final TimeProvider timeProvider;
  private final ApplicationEventPublisher eventPublisher;

  public AupSignatureController(AupSignatureConverter conv, AccountUtils utils,
      IamAupSignatureRepository signatureRepo, IamAupRepository aupRepo, TimeProvider timeProvider,
      ApplicationEventPublisher publisher) {
    this.signatureConverter = conv;
    this.accountUtils = utils;
    this.signatureRepo = signatureRepo;
    this.aupRepo = aupRepo;
    this.timeProvider = timeProvider;
    this.eventPublisher = publisher;
  }

  private Supplier<AupNotFoundError> aupNotFoundException() {
    return () -> new AupNotFoundError();
  }

  private Supplier<AccountNotFoundException> accountNotFoundException(String message) {
    return () -> new AccountNotFoundException(message);
  }

  private Supplier<AupSignatureNotFoundError> signatureNotFound(IamAccount account) {
    return () -> new AupSignatureNotFoundError(account);
  }

  @PostMapping(value = "/iam/aup/signature")
  @PreAuthorize("#iam.hasDashboardRole('ROLE_USER')")
  @ResponseStatus(code = HttpStatus.CREATED)
  public void signAup() throws AccountNotFoundException {

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(accountNotFoundException("Account not found for authenticated user"));

    Date now = new Date(timeProvider.currentTimeMillis());
    IamAupSignature signature = signatureRepo.createSignatureForAccount(aup, account, now);
    eventPublisher.publishEvent(new AupSignedEvent(this, signature));
  }

  @GetMapping(value = "/iam/aup/signature")
  @PreAuthorize("#iam.hasDashboardRole('ROLE_USER')")
  public AupSignatureDTO getSignature() throws AccountNotFoundException {

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
        .orElseThrow(accountNotFoundException("Account not found for authenticated user"));

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());
    IamAupSignature sig =
        signatureRepo.findSignatureForAccount(aup, account).orElseThrow(signatureNotFound(account));
    return signatureConverter.dtoFromEntity(sig);
  }

  @GetMapping(value = "/iam/aup/signature/{accountId}")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_GM') or #iam.isUser(#accountId)")
  public AupSignatureDTO getSignatureForAccount(@PathVariable String accountId) throws AccountNotFoundException {

    IamAccount account = accountUtils.getByAccountId(accountId)
      .orElseThrow(accountNotFoundException("Account not found for id: " + accountId));

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());
    IamAupSignature sig =
        signatureRepo.findSignatureForAccount(aup, account).orElseThrow(signatureNotFound(account));

    return signatureConverter.dtoFromEntity(sig);
  }

  @PatchMapping(value = "/iam/aup/signature/{accountId}")
  @ResponseStatus(value = HttpStatus.CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public AupSignatureDTO updateSignatureForAccount(@PathVariable String accountId) throws AccountNotFoundException {

    IamAccount account = accountUtils.getByAccountId(accountId)
      .orElseThrow(accountNotFoundException("Account not found for id: " + accountId));
    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());
    Date now = new Date(timeProvider.currentTimeMillis());

    IamAupSignature signature = signatureRepo.createSignatureForAccount(aup, account, now);
    eventPublisher.publishEvent(new AupSignedOnBehalfEvent(this, signature, account.getUsername()));

    return signatureConverter.dtoFromEntity(signature);
  }

  @DeleteMapping(value = "/iam/aup/signature/{accountId}")
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void deleteSignatureForAccount(@PathVariable String accountId) throws AccountNotFoundException {

    IamAccount deleterAccount = accountUtils.getAuthenticatedUserAccount()
        .orElseThrow(accountNotFoundException("Account not found for authenticated user"));
    IamAccount signatureAccount = accountUtils.getByAccountId(accountId)
      .orElseThrow(accountNotFoundException("Account not found for id: " + accountId));

    IamAup aup = aupRepo.findDefaultAup().orElseThrow(aupNotFoundException());

    IamAupSignature signature =
        signatureRepo.findSignatureForAccount(aup, signatureAccount).orElseThrow(signatureNotFound(signatureAccount));

    signatureRepo.deleteSignatureForAccount(aup, signatureAccount);
    eventPublisher.publishEvent(new AupSignatureDeletedEvent(this, deleterAccount.getUsername(), signature));
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
}
