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
package it.infn.mw.iam.api.account.lifecycle;

import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL;
import static java.lang.String.format;

import java.util.Date;
import java.util.function.Supplier;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.audit.events.account.AccountEndTimeUpdatedEvent;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

@RestController
@RequestMapping(value = AccountLifecycleController.BASE_RESOURCE)
@PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
public class AccountLifecycleController {

  public static final String BASE_RESOURCE = "/iam/account/{id}/endTime";
  public static final String INVALID_LIFECYCLE_TEMPLATE = "Invalid lifecycle object: %s";
  public static final String READONLY_ENDTIME_MSG =
      "Account end time is read-only for this organization";

  private final IamAccountService service;
  private final LifecycleProperties properties;
  private final ApplicationEventPublisher eventPublisher;

  public AccountLifecycleController(IamAccountService accountService,
      LifecycleProperties properties, ApplicationEventPublisher eventPublisher) {
    this.service = accountService;
    this.properties = properties;
    this.eventPublisher = eventPublisher;
  }

  private Supplier<NoSuchAccountError> noSuchAccountError(String uuid) {
    return () -> NoSuchAccountError.forUuid(uuid);
  }

  private void handleValidationError(BindingResult result) {
    if (result.hasErrors()) {
      throw new InvalidLifecycleError(
          format(INVALID_LIFECYCLE_TEMPLATE, stringifyValidationError(result)));
    }
  }

  @PutMapping
  public void setEndTime(@PathVariable String id, @RequestBody @Validated AccountLifecycleDTO dto,
      BindingResult validationResult) {

    if (properties.getAccount().isReadOnlyEndTime()) {
      throw new InvalidLifecycleError(READONLY_ENDTIME_MSG);
    }

    handleValidationError(validationResult);
    IamAccount account = service.findByUuid(id).orElseThrow(noSuchAccountError(id));
    Date previousEndTime = account.getEndTime();
    account.setEndTime(dto.getEndTime());
    account.removeLabelByName(LIFECYCLE_STATUS_LABEL);
    service.saveAccount(account);
    eventPublisher
      .publishEvent(new AccountEndTimeUpdatedEvent(this, account, previousEndTime, format(
          "Account endTime set to '%s' for user '%s'", dto.getEndTime(), account.getUsername())));
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ErrorDTO invalidRepresentation(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidLifecycleError.class)
  public ErrorDTO invalidLifecycle(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

}
