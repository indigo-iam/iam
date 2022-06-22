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
package it.infn.mw.iam.api.account.client;

import static it.infn.mw.iam.api.utils.ValidationErrorUtils.handleValidationError;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;

import it.infn.mw.iam.api.client.search.service.ClientSearchService;
import it.infn.mw.iam.api.common.ClientViews;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.form.PaginatedRequestForm;

@RestController
@PreAuthorize("hasRole('USER')")
public class AccountClientController {
  public static final String INVALID_PAGINATION_REQUEST = "Invalid pagination request";

  final ClientSearchService clientSearchService;


  @Autowired
  public AccountClientController(ClientSearchService clientSearchService) {

    this.clientSearchService = clientSearchService;
  }


  @JsonView(ClientViews.Limited.class)
  @GetMapping("/iam/account/me/clients")
  public ListResponseDTO<RegisteredClientDTO> getOwnedClients(
      @Validated PaginatedRequestForm form, final BindingResult validationResult) {

    handleValidationError(INVALID_PAGINATION_REQUEST, validationResult);
    return clientSearchService.findOwnedClients(form);
  }

}
