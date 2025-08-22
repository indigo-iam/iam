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
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.oauth.TokenRevocationService;
import it.infn.mw.iam.core.oauth.exceptions.UnauthorizedClientException;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@RestController
public class IamIntrospectionEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(IamIntrospectionEndpoint.class);

  public static final String URL = "introspect";

  private static final String NOT_ALLOWED_CLIENT_ERROR =
      "Client %s is not allowed to call introspection endpoint";
  private static final String SUSPENDED_CLIENT_ERROR =
      "Client %s has been suspended and is not allowed to call introspection endpoint";

  private final OAuth2TokenEntityService tokenService;
  private final ClientDetailsEntityService clientService;
  private final IamAccountService accountService;
  private final TokenRevocationService revocationService;

  public IamIntrospectionEndpoint(OAuth2TokenEntityService tokenService,
      ClientDetailsEntityService clientService,
      IamAccountService accountService,
      TokenRevocationService revocationService) {
    this.tokenService = tokenService;
    this.clientService = clientService;
    this.accountService = accountService;
    this.revocationService = revocationService;
  }

  @PostMapping(value = "/" + URL, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},
      produces = {MediaType.APPLICATION_JSON_VALUE})
  @PreAuthorize("hasRole('ROLE_CLIENT')")
  public IntrospectionResponse introspect(
      @RequestParam(value = "token", required = true) String tokenValue,
      @RequestParam(value = "token_type_hint", required = false) TokenTypeHint tokenType,
      Authentication auth)
      throws UnauthorizedClientException, ParseException, InvalidTokenException {

    ClientDetailsEntity c = loadClient(auth);
    if (tokenType == null) {
      tokenType = getTokenTypeFrom(tokenValue);
    }
    validate(c, tokenValue, tokenType);

    switch (tokenType) {
      case REFRESH_TOKEN:
        return introspectRefreshToken(tokenValue);
      default:
        return introspectAccessToken(tokenValue);
    }
  }

  private void validate(ClientDetailsEntity c, String tokenValue, TokenTypeHint tokenType)
      throws UnauthorizedClientException, InvalidTokenException {

    // check if client has been suspended
    if (!c.isActive()) {
      String errorMsg = String.format(SUSPENDED_CLIENT_ERROR, c.getClientId());
      logger.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }

    // check if client is allowed to introspect tokens
    if (!c.isAllowIntrospection()) {
      String errorMsg = String.format(NOT_ALLOWED_CLIENT_ERROR, c.getClientId());
      logger.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }

    // invalid null token to introspect
    if (Strings.isNullOrEmpty(tokenValue)) {
      String errorMsg = "Verify failed; token value is null";
      logger.error(errorMsg);
      throw new InvalidTokenException(errorMsg);
    }
  }

  private IntrospectionResponse introspectRefreshToken(String token)
      throws ParseException, InvalidTokenException {

    OAuth2RefreshTokenEntity refreshToken = tokenService.getRefreshToken(token);
    if (refreshToken.isExpired()) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    builder.addField("exp", refreshToken.getExpiration());
    refreshToken.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addField);
    return builder.build();
  }

  private IntrospectionResponse introspectAccessToken(String token)
      throws InvalidTokenException, ParseException {

    OAuth2AccessTokenEntity at = tokenService.readAccessToken(token);
    if (at.isExpired() || isRevoked(at)) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    builder.addField("exp", at.getExpiration());
    at.getJwt().getJWTClaimsSet().getClaims().forEach((k, v) -> {
      if (k.equals("sub") && !at.getClient().getClientId().equals(String.valueOf(v))) {
        IamAccount a = accountService.findByUuid(String.valueOf(v))
          .orElseThrow(
              () -> new InvalidTokenException("Token sub doesn't refer to any registered user"));
        builder.addField("user_id", a.getUsername());
      }
      builder.addField(k, v);
    });
    return builder.build();
  }

  private boolean isRevoked(OAuth2AccessTokenEntity at)
      throws InvalidTokenException, ParseException {
    return revocationService.isTokenRevoked(at.getJwt(), TokenTypeHint.ACCESS_TOKEN);
  }

  private ClientDetailsEntity loadClient(Authentication auth) {

    return clientService.loadClientByClientId(
        auth instanceof OAuth2Authentication oauth2 ? oauth2.getOAuth2Request().getClientId()
            : auth.getName());
  }

  private TokenTypeHint getTokenTypeFrom(String token) throws ParseException {

    try {
      PlainJWT.parse(token);
      return TokenTypeHint.REFRESH_TOKEN;
    } catch (ParseException e) {
      // ignore
    }
    SignedJWT.parse(token);
    return TokenTypeHint.ACCESS_TOKEN;
  }

  @ResponseStatus(value = HttpStatus.OK)
  @ExceptionHandler({UnauthorizedClientException.class, InvalidTokenException.class,
      ParseException.class})
  public IntrospectionResponse invalidClientOrToken(HttpServletRequest req, Exception ex) {
    /*
     * From RFC 7663 in case of valid credentials, but the token is not owned by the authenticated
     * client (or client is not allowed to introspect it) the response must be 200 OK with
     * {"active": false}.
     */
    return IntrospectionResponse.inactive();
  }
}
