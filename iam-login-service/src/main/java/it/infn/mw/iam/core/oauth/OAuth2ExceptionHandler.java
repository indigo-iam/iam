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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import it.infn.mw.iam.core.oauth.exceptions.OAuth2ProtocolException;

@SuppressWarnings("deprecation")
@ControllerAdvice
public class OAuth2ExceptionHandler {

  private static final Logger log =
      LoggerFactory.getLogger(OAuth2ExceptionHandler.class);

  private final WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator;

  public OAuth2ExceptionHandler(
      WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator) {
    this.exceptionTranslator = exceptionTranslator;
  }

  @ExceptionHandler(OAuth2Exception.class)
  public ResponseEntity<OAuth2Exception> handleException(OAuth2Exception exception)
      throws Exception {

    log.info(
        "Handling OAuth2 error: type={}, message={}",
        exception.getClass().getSimpleName(),
        exception.getMessage());

    return exceptionTranslator.translate(exception);
  }

  @ExceptionHandler(OAuth2ProtocolException.class)
  public ResponseEntity<OAuth2ErrorResponse> handleOAuth2Exception(OAuth2ProtocolException ex) {

    OAuth2ErrorResponse response =
        new OAuth2ErrorResponse(ex.getError(), ex.getErrorDescription());

    return ResponseEntity.status(ex.getStatus()).body(response);
  }
}