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
package it.infn.mw.iam.api.proxy;

import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.security.Principal;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;

@RestController
@ConditionalOnProperty(name = "proxycert.enabled", havingValue = "true")
public class ProxyCertificatesApiController {

  public static final String PROXY_API_PATH = "/iam/proxycert";
  
  final ProxyCertificateService service;

  @Autowired
  public ProxyCertificatesApiController(ProxyCertificateService service) {
    this.service = service;
  }
  
  private void handleValidationErrors(BindingResult bindingResult) {
    if (bindingResult.hasErrors()) {
      throw new InvalidProxyRequestError(stringifyValidationError(bindingResult));
    }
  }

  @RequestMapping(method=POST, value=PROXY_API_PATH)
  @PreAuthorize("#iam.hasScope('proxy:generate') and hasRole('USER')")
  public ProxyCertificateDTO generateProxy(Principal authenticatedUser,
      @Valid ProxyCertificateRequestDTO request, BindingResult bindingResult) {

    handleValidationErrors(bindingResult);
    
    return service.generateProxy(authenticatedUser, request);
  }
  
  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidProxyRequestError.class)
  @ResponseBody
  public ErrorDTO handleError(InvalidProxyRequestError e) {    
    return ErrorDTO.fromString(e.getMessage());
  }
  
  @ResponseStatus(code = HttpStatus.PRECONDITION_FAILED)
  @ExceptionHandler(ProxyNotFoundError.class)
  @ResponseBody
  public ErrorDTO handleError(ProxyNotFoundError e) {    
    return ErrorDTO.fromString(e.getMessage());
  }
}
