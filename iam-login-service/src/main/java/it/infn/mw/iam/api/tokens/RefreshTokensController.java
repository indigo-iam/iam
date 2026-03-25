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
package it.infn.mw.iam.api.tokens;

import static it.infn.mw.iam.api.tokens.Constants.REFRESH_TOKENS_ENDPOINT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.tokens.exception.TokenNotFoundException;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.service.TokenService;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;
import it.infn.mw.iam.core.user.exception.IamAccountException;

@RestController
@Transactional
@RequestMapping(REFRESH_TOKENS_ENDPOINT)
public class RefreshTokensController extends TokensControllerSupport {

  @Autowired
  private TokenService<RefreshToken> tokenService;

  @GetMapping(produces = APPLICATION_JSON_CONTENT_TYPE)
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public MappingJacksonValue lisRefreshTokens(@RequestParam(required = false) Integer count,
      @RequestParam(required = false) Integer startIndex,
      @RequestParam(required = false) String userId,
      @RequestParam(required = false) String clientId,
      @RequestParam(required = false) final String attributes) {

    TokensPageRequest pr = buildTokensPageRequest(count, startIndex);
    ListResponseDTO<RefreshToken> results = getFilteredList(pr, userId, clientId, tokenService);
    return filterAttributes(results, attributes);
  }

  @DeleteMapping(value = "/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void revokeRefreshToken(@PathVariable Long id) {

    tokenService.revokeTokenById(id);
  }


  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(TokenNotFoundException.class)
  public ErrorDTO tokenNotFoundError(Exception ex) {

    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(IamAccountException.class)
  public ErrorDTO accountNotFoundError(Exception ex) {

    return ErrorDTO.fromString(ex.getMessage());
  }
}
