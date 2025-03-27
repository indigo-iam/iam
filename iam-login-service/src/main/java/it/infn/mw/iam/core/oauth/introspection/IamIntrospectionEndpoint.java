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
package it.infn.mw.iam.core.oauth.introspection;

import java.text.ParseException;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
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

import com.google.common.base.Strings;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.oauth.TokenRevocationService;
import it.infn.mw.iam.core.oauth.exceptions.ClientNotAllowed;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@SuppressWarnings("deprecation")
@RestController
public class IamIntrospectionEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(IamIntrospectionEndpoint.class);

  public static final String URL = "introspect";

  private static final String NOT_ALLOWED_CLIENT_ERROR =
      "Client %s is not allowed to call introspection endpoint";
  private static final String SUSPENDED_CLIENT_ERROR =
      "Client %s has been suspended and is not allowed to call introspection endpoint";

  private final OAuth2TokenEntityService tokenServices;
  private final ClientDetailsEntityService clientService;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamAccountRepository accountRepository;
  private final TokenRevocationService revocationService;

  public IamIntrospectionEndpoint(OAuth2TokenEntityService tokenServices,
      ClientDetailsEntityService clientService, IamOAuthRefreshTokenRepository refreshTokenRepo,
      IamAccountRepository accountRepository, TokenRevocationService revocationService) {
    this.tokenServices = tokenServices;
    this.clientService = clientService;
    this.refreshTokenRepo = refreshTokenRepo;
    this.accountRepository = accountRepository;
    this.revocationService = revocationService;
  }

  @PostMapping(value = "/" + URL, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},
      produces = {MediaType.APPLICATION_JSON_VALUE})
  @PreAuthorize("hasRole('ROLE_CLIENT')")
  public IntrospectionResponse verify(
      @RequestParam(value = "token", required = true) String tokenValue,
      @RequestParam(value = "token_type_hint", required = false) TokenTypeHint tokenType,
      Authentication auth) throws ClientNotAllowed, ParseException {

    ClientDetailsEntity c = loadClient(auth);

    // check client is suspended
    if (!c.isActive()) {
      String errorMsg = String.format(SUSPENDED_CLIENT_ERROR, c.getClientId());
      logger.error(errorMsg);
      throw new ClientNotAllowed(errorMsg);
    }

    // check client is allowed to introspect tokens
    if (!c.isAllowIntrospection()) {
      String errorMsg = String.format(NOT_ALLOWED_CLIENT_ERROR, c.getClientId());
      logger.error(errorMsg);
      throw new ClientNotAllowed(errorMsg);
    }

    // invalid null token to introspect
    if (Strings.isNullOrEmpty(tokenValue)) {
      logger.error("Verify failed; token value is null");
      return IntrospectionResponse.inactive();
    }

    if (tokenType == null) {
      try {
        if (refreshTokenRepo.findByTokenValue(PlainJWT.parse(tokenValue)).isPresent()) {
          return introspectRefreshToken(tokenValue);
        }
      } catch (ParseException e) {
        // skip
      }
      return introspectAccessToken(tokenValue);
    }

    switch (tokenType) {
      case REFRESH_TOKEN:
        return introspectRefreshToken(tokenValue);
      case ACCESS_TOKEN:
      default:
        return introspectAccessToken(tokenValue);
    }
  }

  private IntrospectionResponse introspectRefreshToken(String tokenValue) throws ParseException {

    Optional<OAuth2RefreshTokenEntity> refreshToken =
        refreshTokenRepo.findByTokenValue(PlainJWT.parse(tokenValue));
    if (refreshToken.isEmpty() || refreshToken.get().isExpired()) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    builder.addField("exp", refreshToken.get().getExpiration());
    refreshToken.get()
      .getJwt()
      .getJWTClaimsSet()
      .getClaims()
      .forEach(builder::addField);
    return builder.build();
  }

  private IntrospectionResponse introspectAccessToken(String tokenValue)
      throws InvalidTokenException, ParseException {

    OAuth2AccessTokenEntity accessToken = tokenServices.readAccessToken(tokenValue);
    if (accessToken.isExpired() || isRevoked(tokenValue)) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    builder.addField("exp", accessToken.getExpiration());
    accessToken.getJwt().getJWTClaimsSet().getClaims().forEach((k, v) -> {
      if (k.equals("sub") && !accessToken.getClient().getClientId().equals(String.valueOf(v))) {
        IamAccount a = accountRepository.findByUuid(String.valueOf(v))
          .orElseThrow(
              () -> new InvalidTokenException("Token sub doesn't refer to any registered user"));
        builder.addField("user_id", a.getUsername());
      }
      builder.addField(k, v);
    });
    return builder.build();
  }

  private boolean isRevoked(String tokenValue) {
    return revocationService.isAccessTokenRevoked(tokenValue);
  }

  private ClientDetailsEntity loadClient(Authentication auth) {

    return clientService.loadClientByClientId(
        auth instanceof OAuth2Authentication oauth2 ? oauth2.getOAuth2Request().getClientId()
            : auth.getName());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ParseException.class)
  public ErrorDTO errorOnParsingToken(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidTokenException.class)
  public ErrorDTO invalidToken(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(ClientNotAllowed.class)
  public ErrorDTO clientNotAllowed(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
