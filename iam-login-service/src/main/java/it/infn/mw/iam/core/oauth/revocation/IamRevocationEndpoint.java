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
package it.infn.mw.iam.core.oauth.revocation;

import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.oauth.exceptions.UnauthorizedClientException;

@SuppressWarnings("deprecation")
@RestController
public class IamRevocationEndpoint {

  public static final Logger LOG = LoggerFactory.getLogger(IamRevocationEndpoint.class);

  private static final String SUSPENDED_CLIENT_ERROR =
      "Client %s has been suspended and is not allowed to revoke any token";
  private static final String NOT_ALLOWED_CLIENT_ERROR =
      "Client %s is not allowed to revoke a not owned token";

  private final TokenRevocationService revocationService;
  private final ClientDetailsEntityService clientService;
  private final IamTokenService tokenService;

  public IamRevocationEndpoint(TokenRevocationService revocationService,
      ClientDetailsEntityService clientService, IamTokenService tokenService) {
    this.revocationService = revocationService;
    this.clientService = clientService;
    this.tokenService = tokenService;
  }

  @PostMapping(value = "/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @PreAuthorize("hasRole('ROLE_CLIENT')")
  public void revoke(@RequestParam(name = OAuth2ParameterNames.TOKEN) String tokenValue,
      Authentication auth)
      throws UnauthorizedClientException, ParseException, InvalidTokenException {

    ClientDetailsEntity authenticatedClient = loadClient(auth);
    JWT jwt = JWTParser.parse(tokenValue);

    /*
     * Currently IAM issues access tokens as a Signed JWT while refresh tokens are Plain JWT
     */
    if (jwt instanceof PlainJWT) {
      OAuth2RefreshTokenEntity refreshToken = tokenService.getRefreshToken(tokenValue);
      ClientDetailsEntity tokenClient = refreshToken.getClient();
      verifyClient(tokenClient, authenticatedClient);
      revocationService.revokeRefreshToken(refreshToken);
    }
    if (jwt instanceof SignedJWT) {
      OAuth2AccessTokenEntity accessToken = tokenService.readAccessToken(tokenValue);
      ClientDetailsEntity tokenClient = accessToken.getClient();
      verifyClient(tokenClient, authenticatedClient);
      revocationService.revokeAccessToken(accessToken);
    }
    throw new InvalidTokenException("Expected a SignedJWT or PlainJWT object");
  }

  private void verifyClient(ClientDetailsEntity tokenClient,
      ClientDetailsEntity authenticatedClient) throws UnauthorizedClientException {

    // check if client has been suspended
    if (!authenticatedClient.isActive()) {
      String errorMsg = String.format(SUSPENDED_CLIENT_ERROR, authenticatedClient.getClientId());
      LOG.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }

    if (!tokenClient.getClientId().equals(authenticatedClient.getClientId())) {
      String errorMsg = String.format(NOT_ALLOWED_CLIENT_ERROR, authenticatedClient.getClientId());
      LOG.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }
  }

  private ClientDetailsEntity loadClient(Authentication auth) {

    return clientService.loadClientByClientId(
        auth instanceof OAuth2Authentication oauth2 ? oauth2.getOAuth2Request().getClientId()
            : auth.getName());
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
