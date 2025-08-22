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

import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.oauth.exceptions.UnauthorizedClientException;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@RestController
public class IamRevocationEndpoint {

  public static final String TOKEN_PARAM = "token";
  public static final String TOKEN_TYPE_HINT_PARAM = "token_type_hint";
  public static final Logger LOG = LoggerFactory.getLogger(IamRevocationEndpoint.class);

  public static final String URL = "revoke";

  private final IamTokenService tokenService;
  private final TokenRevocationService revocationService;
  private final IamClientRepository clientRepo;

  public IamRevocationEndpoint(IamTokenService tokenService, TokenRevocationService revocationService,
      IamClientRepository clientRepo) {
    this.tokenService = tokenService;
    this.revocationService = revocationService;
    this.clientRepo = clientRepo;
  }

  @PostMapping(value = "/" + URL, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @PreAuthorize("hasRole('ROLE_CLIENT')")
  public void revoke(@RequestParam(name = TOKEN_PARAM, required = true) String tokenValue,
      @RequestParam(name = TOKEN_TYPE_HINT_PARAM, required = false) TokenTypeHint tokenType,
      Authentication auth)
      throws UnauthorizedClientException, ParseException, InvalidTokenException {

    ClientDetailsEntity authenticatedClient = loadAuthenticatedClient(auth);
    JWT jwt = JWTParser.parse(tokenValue);
    tokenType = tokenType == null ? TokenTypeHint.valueFrom(jwt) : tokenType;
    checkAuthorization(authenticatedClient, jwt, tokenType);
    revocationService.revokeToken(jwt, tokenType);
  }

  private void checkAuthorization(ClientDetailsEntity authenticatedClient, JWT jwt, TokenTypeHint tokenType) throws UnauthorizedClientException {

    ClientDetailsEntity client = tokenService.getClientForToken(jwt, tokenType);
    if (!authenticatedClient.getClientId()
        .equals(client.getClientId())) {
      throw new UnauthorizedClientException();
    }
  }

  private ClientDetailsEntity loadAuthenticatedClient(Authentication auth) {

    String clientId = auth instanceof OAuth2Authentication oauth2authentication
        ? oauth2authentication.getOAuth2Request().getClientId()
        : auth.getName();
    return clientRepo.findByClientId(clientId)
      .orElseThrow(() -> new IllegalStateException("Unable to find the authenticated client"));
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(UnauthorizedClientException.class)
  public ErrorDTO clientIsNotTheIssuerError(HttpServletRequest req, Exception ex) {

    return ErrorDTO.fromString("unauthorized_client");
  }

  @ResponseStatus(value = HttpStatus.OK)
  @ExceptionHandler({IllegalArgumentException.class, ParseException.class,
      InvalidTokenException.class, IllegalArgumentException.class})
  public void invalidTokenRequest(HttpServletRequest req, Exception ex) {
    /*
     * From RFC-7009: invalid tokens do not cause an error response since the client cannot handle
     * such an error in a reasonable way. Moreover, the purpose of the revocation request,
     * invalidating the particular token, is already achieved.
     */
  }
}
