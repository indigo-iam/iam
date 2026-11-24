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
package it.infn.mw.iam.api.common;

import java.sql.SQLException;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import it.infn.mw.iam.api.account.authority.AccountAuthorityController;
import it.infn.mw.iam.api.account.group_manager.AccountGroupManagerController;
import it.infn.mw.iam.registration.RegistrationApiController;

/**
 * Requests that lose a race with a concurrent change of the same resources (a deadlock, a lock
 * that cannot be acquired, a row removed meanwhile) get a conflict error and can be retried.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = {AccountAuthorityController.class,
    AccountGroupManagerController.class, RegistrationApiController.class})
public class ConcurrentChangeExceptionHandler {

  private static final ErrorDTO CONFLICT =
      ErrorDTO.fromString("The resource was changed by another request, please retry");

  @ResponseStatus(HttpStatus.CONFLICT)
  @ExceptionHandler(ConcurrencyFailureException.class)
  public ErrorDTO concurrencyFailure(ConcurrencyFailureException e) {
    return CONFLICT;
  }

  @ResponseStatus(HttpStatus.CONFLICT)
  @ExceptionHandler(TransactionSystemException.class)
  public ErrorDTO commitFailure(TransactionSystemException e) {
    for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
      if (cause instanceof SQLException) {
        return CONFLICT;
      }
    }
    throw e;
  }
}
