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
package it.infn.mw.iam.api.account.attributes;

import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static java.lang.String.format;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.AttributeDTO;
import it.infn.mw.iam.api.common.AttributeDTOConverter;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.InvalidAttributeError;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAttribute;

@RestController
public class AccountAttributesController {

  public static final String INVALID_ATTRIBUTE_TEMPLATE = "Invalid attribute: %s";


  final IamAccountService accountService;
  final AttributeDTOConverter converter;

  @Autowired
  public AccountAttributesController(IamAccountService accountService,
      AttributeDTOConverter converter) {
    this.converter = converter;
    this.accountService = accountService;
  }
  
  private void handleValidationError(BindingResult result) {
    if (result.hasErrors()) {
      throw new InvalidAttributeError(
          format(INVALID_ATTRIBUTE_TEMPLATE, stringifyValidationError(result)));
    }
  }

  @RequestMapping(value = "/iam/account/{id}/attributes", method=RequestMethod.GET)
  @PreAuthorize("hasRole('ADMIN') or #iam.isUser(#id)")
  public List<AttributeDTO> getAttributes(@PathVariable String id) {

    IamAccount account =
        accountService.findByUuid(id).orElseThrow(() -> NoSuchAccountError.forUuid(id));

    List<AttributeDTO> results = Lists.newArrayList();
    account.getAttributes().forEach(a -> results.add(converter.dtoFromEntity(a)));

    return results;
  }

  @RequestMapping(value = "/iam/account/{id}/attributes", method= PUT)
  @PreAuthorize("hasRole('ADMIN')")
  public void setAttribute(@PathVariable String id, @RequestBody @Validated AttributeDTO attribute,
      final BindingResult validationResult) {

    handleValidationError(validationResult);
    IamAccount account =
        accountService.findByUuid(id).orElseThrow(() -> NoSuchAccountError.forUuid(id));
    
    IamAttribute attr = converter.entityFromDto(attribute);
    
    accountService.setAttribute(account, attr);
  }
  
  @RequestMapping(value = "/iam/account/{id}/attributes", method= DELETE)
  @PreAuthorize("hasRole('ADMIN')")
  @ResponseStatus(value = NO_CONTENT)
  public void deleteAttribute(@PathVariable String id, @Validated AttributeDTO attribute,
      final BindingResult validationResult) {
    
    handleValidationError(validationResult);
    IamAccount account =
        accountService.findByUuid(id).orElseThrow(() -> NoSuchAccountError.forUuid(id));
    IamAttribute attr = converter.entityFromDto(attribute);
    
    accountService.deleteAttribute(account, attr);
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidAttributeError.class)
  @ResponseBody
  public ErrorDTO handleValidationError(InvalidAttributeError e) {    
    return ErrorDTO.fromString(e.getMessage());
  }
  
  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchAccountError.class)
  @ResponseBody
  public ErrorDTO handleNoSuchAccountError(NoSuchAccountError e) {    
    return ErrorDTO.fromString(e.getMessage());
  }
  
}
