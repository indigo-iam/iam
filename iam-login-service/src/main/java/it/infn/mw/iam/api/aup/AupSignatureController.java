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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.error.AupSignatureNotFoundError;
import it.infn.mw.iam.api.aup.model.AupSignatureConverter;
import it.infn.mw.iam.api.aup.model.AupSignatureDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.audit.events.aup.AupSignedEvent;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;

@RestController
@Transactional
public class AupSignatureController {

  private final AupSignatureConverter signatureConverter;
  private final AccountUtils accountUtils;
  private final IamAupSignatureRepository signatureRepo;
  private final TimeProvider timeProvider;
  private final ApplicationEventPublisher eventPublisher;

  @Autowired
  public AupSignatureController(AupSignatureConverter conv, AccountUtils utils,
      IamAupSignatureRepository signatureRepo, TimeProvider timeProvider,
      ApplicationEventPublisher publisher) {
    this.signatureConverter = conv;
    this.accountUtils = utils;
    this.signatureRepo = signatureRepo;
    this.timeProvider = timeProvider;
    this.eventPublisher = publisher;
  }

  private Supplier<IllegalStateException> accountNotFoundException(String message) {
    return () -> new IllegalStateException(message);
  }
  
  private Supplier<AupSignatureNotFoundError> signatureNotFound(IamAccount account){
    return () -> new AupSignatureNotFoundError(account);
  }

  @RequestMapping(value = "/iam/aup/signature", method = RequestMethod.POST)
  @PreAuthorize("hasRole('USER')")
  @ResponseStatus(code = HttpStatus.CREATED)
  public void signAup() {
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(accountNotFoundException("Account not found for authenticated user"));

    Date now = new Date(timeProvider.currentTimeMillis());
    IamAupSignature signature = signatureRepo.createSignatureForAccount(account, now);
    eventPublisher.publishEvent(new AupSignedEvent(this, signature));

  }

  @RequestMapping(value = "/iam/aup/signature", method = RequestMethod.GET)
  @PreAuthorize("hasRole('USER')")
  public AupSignatureDTO getSignature() {
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(accountNotFoundException("Account not found for authenticated user"));


    IamAupSignature sig = signatureRepo.findSignatureForAccount(account)
      .orElseThrow(signatureNotFound(account));

    return signatureConverter.dtoFromEntity(sig);
  }

  @RequestMapping(value = "/iam/aup/signature/{accountId}", method = RequestMethod.GET)
  @PreAuthorize("hasRole('ADMIN') or #iam.isUser(#accountId)")
  public AupSignatureDTO getSignatureForAccount(@PathVariable String accountId) {
    IamAccount account = accountUtils.getByAccountId(accountId)
      .orElseThrow(accountNotFoundException("Account not found for id: " + accountId));
    
    IamAupSignature sig = signatureRepo.findSignatureForAccount(account)
        .orElseThrow(signatureNotFound(account));

      return signatureConverter.dtoFromEntity(sig);
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(AupSignatureNotFoundError.class)
  public ErrorDTO notFoundError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
