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
  @ExceptionHandler(ScimException.class)
  @ResponseBody
  public ScimErrorResponse handleInvalidArgumentException(ScimException e) {

    return buildErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
  }

  private ScimErrorResponse buildErrorResponse(HttpStatus status, String message) {

    return new ScimErrorResponse(status.value(), message);
  }
}
