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
package it.infn.mw.iam.api.client.search;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolationException;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;

import it.infn.mw.iam.api.client.search.service.ClientSearchService;
import it.infn.mw.iam.api.common.ClientViews;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

@RestController
@RequestMapping(SearchClientController.ENDPOINT)
@PreAuthorize("hasRole('ADMIN')")
public class SearchClientController {

  public static final int MAX_PAGE_SIZE = 100;

  public static final String ENDPOINT = "/iam/api/search/clients";
  public static final String INVALID_FIND_CLIENT_REQUEST = "Invalid find client request";

  private final ClientSearchService service;

  public SearchClientController(ClientSearchService service) {
    this.service = service;
  }

  @JsonView({ClientViews.ClientManagement.class})
  @GetMapping
  public ListResponseDTO<RegisteredClientDTO> searchClients(
      ClientSearchForm searchForm) {
    return service.searchClients(searchForm);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ConstraintViolationException.class)
  public ErrorDTO constraintValidationError(HttpServletRequest req, Exception ex) {
    return ErrorDTO
      .fromString(String.format("%s: %s", INVALID_FIND_CLIENT_REQUEST, ex.getMessage()));
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(IllegalArgumentException.class)
  public ErrorDTO illegalArgumentError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

}