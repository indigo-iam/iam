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
package it.infn.mw.iam.api.scim.controller;

import org.apache.commons.lang.NotImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.exception.ScimValidationException;
import it.infn.mw.iam.api.scim.model.ScimErrorResponse;
import it.infn.mw.iam.authn.x509.CertificateParsingError;
import it.infn.mw.iam.core.group.error.InvalidGroupOperationError;
import it.infn.mw.iam.util.ssh.InvalidSshKeyException;

@ControllerAdvice
public class ScimExceptionHandler extends ResponseEntityExceptionHandler {

  public static final Logger LOG = LoggerFactory.getLogger(ScimExceptionHandler.class);

  @ResponseStatus(code = HttpStatus.NOT_IMPLEMENTED)
  @ExceptionHandler(NotImplementedException.class)
  @ResponseBody
  public ScimErrorResponse handleNotImplementedException(NotImplementedException e) {

    return buildErrorResponse(HttpStatus.NOT_IMPLEMENTED, e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ScimValidationException.class)
  @ResponseBody
  public ScimErrorResponse handleScimValidationException(ScimValidationException e) {

    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(CertificateParsingError.class)
  @ResponseBody
  public ScimErrorResponse handleCertificateParsingError(CertificateParsingError e) {

    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(IllegalArgumentException.class)
  @ResponseBody
  public ScimErrorResponse handleInvalidArgumentException(IllegalArgumentException e) {

    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidSshKeyException.class)
  @ResponseBody
  public ScimErrorResponse handleInvalidArgumentException(InvalidSshKeyException e) {

    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(ScimResourceNotFoundException.class)
  @ResponseBody
  public ScimErrorResponse handleResourceNotFoundException(ScimResourceNotFoundException nfe) {

    return buildErrorResponse(HttpStatus.NOT_FOUND, nfe.getMessage());
  }

  @ResponseStatus(code = HttpStatus.CONFLICT)
  @ExceptionHandler(ScimResourceExistsException.class)
  @ResponseBody
  public ScimErrorResponse handleResourceExists(ScimResourceExistsException e) {
    return buildErrorResponse(HttpStatus.CONFLICT, e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ScimPatchOperationNotSupported.class)
  @ResponseBody
  public ScimErrorResponse handleInvalidArgumentException(ScimPatchOperationNotSupported e) {

    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidGroupOperationError.class)
  @ResponseBody
  public ScimErrorResponse handleInvalidGroupOperationException(InvalidGroupOperationError e) {
    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }
  
  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ScimException.class)
  @ResponseBody
  public ScimErrorResponse handleInvalidArgumentException(ScimException e) {

    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }

  private ScimErrorResponse buildErrorResponse(HttpStatus status, String message) {

    return new ScimErrorResponse(status.value(), message);
  }
}
