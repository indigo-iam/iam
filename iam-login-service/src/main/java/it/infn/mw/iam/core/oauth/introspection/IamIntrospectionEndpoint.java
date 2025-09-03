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
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;

import org.apache.tomcat.util.buf.StringUtils;
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
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.oauth.exceptions.UnauthorizedClientException;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse.Builder;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@RestController
public class IamIntrospectionEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(IamIntrospectionEndpoint.class);

  private static final String NOT_ALLOWED_CLIENT_ERROR =
      "Client %s is not allowed to call introspection endpoint";
  private static final String SUSPENDED_CLIENT_ERROR =
      "Client %s has been suspended and is not allowed to call introspection endpoint";

  private final OAuth2TokenEntityService tokenService;
  private final ClientDetailsEntityService clientService;
  private final IamAccountService accountService;
  private final TokenRevocationService revocationService;

  public IamIntrospectionEndpoint(OAuth2TokenEntityService tokenService,
      ClientDetailsEntityService clientService, IamAccountService accountService,
      TokenRevocationService revocationService) {

    this.tokenService = tokenService;
    this.clientService = clientService;
    this.accountService = accountService;
    this.revocationService = revocationService;
  }

  @PostMapping(value = "/introspect", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},
      produces = {MediaType.APPLICATION_JSON_VALUE})
  @PreAuthorize("hasRole('ROLE_CLIENT')")
  public IntrospectionResponse introspect(
      @RequestParam(value = OAuth2ParameterNames.TOKEN, required = true) String tokenValue,
      @RequestParam(value = OAuth2ParameterNames.TOKEN_TYPE_HINT,
          required = false) TokenTypeHint tokenType,
      Authentication auth)
      throws UnauthorizedClientException, ParseException, InvalidTokenException {

    ClientDetailsEntity c = loadClient(auth);
    validate(c, tokenValue);

    if (tokenType == null) {
      tokenType = valueFrom(tokenValue);
    }

    if (TokenTypeHint.REFRESH_TOKEN.equals(tokenType)) {
      return introspectRefreshToken(tokenValue);
    }
    return introspectAccessToken(tokenValue);
  }

  private TokenTypeHint valueFrom(String tokenValue) throws ParseException {

    JWT jwt = JWTParser.parse(tokenValue);
    if (jwt instanceof PlainJWT) {
      return TokenTypeHint.REFRESH_TOKEN;
    }
    if (jwt instanceof SignedJWT) {
      return TokenTypeHint.ACCESS_TOKEN;
    }
    throw new InvalidTokenException("Expected a SignedJWT or PlainJWT object");
  }

  private void validate(ClientDetailsEntity c, String tokenValue)
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

    OAuth2RefreshTokenEntity rt = tokenService.getRefreshToken(token);
    if (rt.isExpired()) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    // base response: copy all claims
    rt.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addField);
    // token type
    builder.addField(OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE, TokenTypeHint.REFRESH_TOKEN);
    builder.addField(OAuth2TokenIntrospectionClaimNames.SUB,
        rt.getJwt().getJWTClaimsSet().getSubject());
    builder.addField(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, rt.getClient().getClientId());
    includeIfNotNull(builder, "client_name", rt.getClient().getClientName());
    includeIfNotNull(builder, "client_last_used", rt.getClient().getClientLastUsed());
    builder.addField(OAuth2TokenIntrospectionClaimNames.EXP, rt.getExpiration());
    return builder.build();
  }

  private IntrospectionResponse introspectAccessToken(String token)
      throws InvalidTokenException, ParseException {

    OAuth2AccessTokenEntity at = tokenService.readAccessToken(token);
    if (at.isExpired() || isRevoked(at)) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    // base response: copy all token claims
    at.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addField);
    // token type
    builder.addField(OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE, TokenTypeHint.ACCESS_TOKEN);
    // override/populate more claims
    String subject = at.getJwt().getJWTClaimsSet().getSubject();
    String clientId = at.getClient().getClientId();
    builder.addField(OAuth2TokenIntrospectionClaimNames.SUB, subject);
    builder.addField(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, clientId);
    includeIfNotNull(builder, "client_name", at.getClient().getClientName());
    includeIfNotNull(builder, "client_last_used", at.getClient().getClientLastUsed());
    builder.addField(OAuth2TokenIntrospectionClaimNames.EXP, at.getExpiration());
    builder.addField(OAuth2TokenIntrospectionClaimNames.IAT,
        at.getJwt().getJWTClaimsSet().getIssueTime());
    builder.addField(OAuth2TokenIntrospectionClaimNames.ISS,
        at.getJwt().getJWTClaimsSet().getIssuer());
    builder.addField(OAuth2TokenIntrospectionClaimNames.JTI,
        at.getJwt().getJWTClaimsSet().getJWTID());
    includeIfNotNull(builder, OAuth2TokenIntrospectionClaimNames.NBF,
        at.getJwt().getJWTClaimsSet().getNotBeforeTime());
    includeIfNotEmpty(builder, OAuth2TokenIntrospectionClaimNames.AUD,
        at.getJwt().getJWTClaimsSet().getAudience());
    includeIfNotEmpty(builder, OAuth2TokenIntrospectionClaimNames.SCOPE, at.getScope());

    if (!clientId.equals(subject)) {
      IamAccount a = accountService.findByUuid(subject)
        .orElseThrow(
            () -> new IllegalStateException("Token sub doesn't refer to any registered user"));
      builder.addField(OAuth2TokenIntrospectionClaimNames.USERNAME, a.getUsername());
      // backward compatibility
      builder.addField("user_id", a.getUsername());
      if (at.getScope().contains(OidcScopes.PROFILE)) {
        includeIfNotNull(builder, StandardClaimNames.GIVEN_NAME, a.getUserInfo().getGivenName());
        includeIfNotNull(builder, StandardClaimNames.MIDDLE_NAME, a.getUserInfo().getMiddleName());
        includeIfNotNull(builder, StandardClaimNames.FAMILY_NAME, a.getUserInfo().getFamilyName());
        includeIfNotNull(builder, StandardClaimNames.NAME, a.getUserInfo().getName());
        includeIfNotNull(builder, StandardClaimNames.NICKNAME, a.getUserInfo().getNickname());
        includeIfNotNull(builder, StandardClaimNames.PICTURE, a.getUserInfo().getPicture());
        includeIfNotNull(builder, "affiliation", a.getUserInfo().getAffiliation());
        includeIfNotNull(builder, StandardClaimNames.PREFERRED_USERNAME,
            a.getUserInfo().getPreferredUsername());
        includeIfNotNull(builder, StandardClaimNames.UPDATED_AT, a.getLastUpdateTime());
        includeIfNotNull(builder, "last_login_at", a.getLastLoginTime());
      }
      if (at.getScope().contains(OidcScopes.EMAIL)) {
        builder.addField(StandardClaimNames.EMAIL, a.getUserInfo().getEmail());
        builder.addField(StandardClaimNames.EMAIL_VERIFIED, a.getUserInfo().getEmailVerified());
      }
    }
    return builder.build();
  }

  private void includeIfNotNull(Builder builder, String key, Object value) {

    if (value != null) {
      builder.addField(key, value.toString());
    }
  }

  private void includeIfNotEmpty(Builder builder, String key, Collection<String> value) {

    if (!value.isEmpty()) {
      builder.addField(key, StringUtils.join(value, ' '));
    }
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

  @ResponseStatus(value = HttpStatus.OK)
  @ExceptionHandler({UnauthorizedClientException.class, InvalidTokenException.class,
      ParseException.class})
  public IntrospectionResponse invalidClientOrToken(HttpServletRequest req, Exception ex) {
    /*
     * From RFC 7663: in case of valid credentials but the token is not owned by the authenticated
     * client (or client is not allowed to introspect it) the response must be 200 OK with
     * {"active": false}.
     */
    return IntrospectionResponse.inactive();
  }
}
