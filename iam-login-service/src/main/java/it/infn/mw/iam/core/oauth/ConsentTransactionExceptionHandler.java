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
package it.infn.mw.iam.core.oauth;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ConsentTransactionExceptionHandler {

  @ExceptionHandler(InvalidConsentTransactionException.class)
  public ResponseEntity<Map<String, String>> handleInvalidConsentTransaction(
      InvalidConsentTransactionException ex) {

    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
      .body(Map.of("error", "invalid_consent_transaction", "message",
          "Invalid or superseded consent transaction. "
              + "Please restart authorization from the application."));
  }
}
