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
