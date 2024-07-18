package it.infn.mw.iam.core.oauth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import it.infn.mw.iam.api.common.ErrorDTO;

@ControllerAdvice
public class AdminScopeNotAllowedExceptionHandler extends ResponseEntityExceptionHandler {

  @ResponseStatus(code = HttpStatus.FORBIDDEN)
  @ExceptionHandler(AdminScopeNotAllowedException.class)
  @ResponseBody
  public ErrorDTO handleValidationException(AdminScopeNotAllowedException e) {

    return buildErrorResponse(e.getMessage());
  }
  
  private ErrorDTO buildErrorResponse(String message) {
    return ErrorDTO.fromString(message);
  }
}
