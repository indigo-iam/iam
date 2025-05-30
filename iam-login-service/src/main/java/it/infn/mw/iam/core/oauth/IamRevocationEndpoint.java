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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.oauth.exceptions.ClientNotAllowed;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@SuppressWarnings("deprecation")
@RestController
public class IamRevocationEndpoint {

  public static final String TOKEN_PARAM = "token";
  public static final String TOKEN_TYPE_HINT_PARAM = "token_type_hint";
  public static final Logger LOG = LoggerFactory.getLogger(IamRevocationEndpoint.class);

  public static final String URL = "revoke";

  private final TokenRevocationService revocationService;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;

  public IamRevocationEndpoint(TokenRevocationService revocationService,
      IamOAuthRefreshTokenRepository refreshTokenRepo) {
    this.revocationService = revocationService;
    this.refreshTokenRepo = refreshTokenRepo;
  }

  @PostMapping(value = "/" + URL, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @PreAuthorize("hasRole('ROLE_CLIENT')")
  public void revoke(@RequestParam(name = TOKEN_PARAM, required = true) String tokenValue,
      @RequestParam(name = TOKEN_TYPE_HINT_PARAM, required = false) TokenTypeHint tokenType,
      Authentication auth) throws ClientNotAllowed {

    String clientId = loadClientId(auth);

    if (tokenType == null) {
      tokenType = TokenTypeHint.ACCESS_TOKEN;
      try {
        if (refreshTokenRepo.findByTokenValue(PlainJWT.parse(tokenValue)).isPresent()) {
          tokenType = TokenTypeHint.REFRESH_TOKEN;
        }
      } catch (ParseException e) {
        // ignore and keep tokenType as ACCESS_TOKEN
      }
    }

    switch (tokenType) {
      case ACCESS_TOKEN:
        revocationService.revokeAccessToken(clientId, tokenValue);
        break;
      case REFRESH_TOKEN:
        default:
        revocationService.revokeRefreshToken(clientId, tokenValue);
        break;
    }
  }

  private String loadClientId(Authentication auth) {

    return auth instanceof OAuth2Authentication oauth2authentication
        ? oauth2authentication.getOAuth2Request().getClientId()
        : auth.getName();
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(ClientNotAllowed.class)
  public ErrorDTO clientIsNotTheIssuerError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
