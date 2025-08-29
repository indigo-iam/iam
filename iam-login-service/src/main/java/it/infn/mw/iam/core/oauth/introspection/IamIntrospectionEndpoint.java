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

import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.AUD_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.CLIENT_ID_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.EXP_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.IAT_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.ISS_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.JTI_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.NBF_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.SCOPE_CLAIM;
import static it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims.SUB_CLAIM;

import java.text.ParseException;
import java.util.List;

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
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.base.Strings;
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

    OAuth2RefreshTokenEntity rt = tokenService.getRefreshToken(token);
    if (rt.isExpired()) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    // base response: copy all claims
    rt.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addField);
    // token type
    builder.addField("token_type", TokenTypeHint.ACCESS_TOKEN);
    builder.addField(SUB_CLAIM, rt.getJwt().getJWTClaimsSet().getSubject());
    builder.addField(CLIENT_ID_CLAIM, rt.getClient().getClientId());
    includeIfNotNull(builder, "client_name", rt.getClient().getClientName());
    includeIfNotNull(builder, "client_last_used", rt.getClient().getClientLastUsed());
    builder.addField(EXP_CLAIM, rt.getExpiration());
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
    at.getJwt().getJWTClaimsSet().getClaims().forEach((k, v) -> {
      builder.addField(k, v);
    });
    // token type
    builder.addField("token_type", TokenTypeHint.ACCESS_TOKEN);
    // override/populate more claims
    String subject = at.getJwt().getJWTClaimsSet().getSubject();
    String clientId = at.getClient().getClientId();
    builder.addField(SUB_CLAIM, subject);
    builder.addField(CLIENT_ID_CLAIM, clientId);
    includeIfNotNull(builder, "client_name", at.getClient().getClientName());
    includeIfNotNull(builder, "client_last_used", at.getClient().getClientLastUsed());
    builder.addField(EXP_CLAIM, at.getExpiration());
    builder.addField(IAT_CLAIM, at.getJwt().getJWTClaimsSet().getIssueTime());
    builder.addField(ISS_CLAIM, at.getJwt().getJWTClaimsSet().getIssuer());
    builder.addField(JTI_CLAIM, at.getJwt().getJWTClaimsSet().getJWTID());
    includeIfNotNull(builder, NBF_CLAIM, at.getJwt().getJWTClaimsSet().getNotBeforeTime());
    List<String> audience = at.getJwt().getJWTClaimsSet().getAudience();
    if (!audience.isEmpty()) {
      builder.addField(AUD_CLAIM, StringUtils.join(audience, ' '));
    }
    if (!at.getScope().isEmpty()) {
      builder.addField(SCOPE_CLAIM, StringUtils.join(at.getScope(), ' '));
    }
    // backward compatibility
    builder.addField("expires_at", at.getExpiration());
    if (!clientId.equals(subject)) {
      IamAccount a = accountService.findByUuid(subject)
        .orElseThrow(
            () -> new InvalidTokenException("Token sub doesn't refer to any registered user"));
      builder.addField("username", a.getUsername());
      // backward compatibility
      builder.addField("user_id", a.getUsername());
      if (at.getScope().contains("profile")) {
        includeIfNotNull(builder, "given_name", a.getUserInfo().getGivenName());
        includeIfNotNull(builder, "middle_name", a.getUserInfo().getMiddleName());
        includeIfNotNull(builder, "family_name", a.getUserInfo().getFamilyName());
        includeIfNotNull(builder, "name", a.getUserInfo().getName());
        includeIfNotNull(builder, "nickname", a.getUserInfo().getNickname());
        includeIfNotNull(builder, "picture", a.getUserInfo().getPicture());
        includeIfNotNull(builder, "affiliation", a.getUserInfo().getAffiliation());
        includeIfNotNull(builder, "preferred_username", a.getUserInfo().getPreferredUsername());
        includeIfNotNull(builder, "updated_at", a.getLastUpdateTime());
        includeIfNotNull(builder, "last_login_at", a.getLastLoginTime());
      }
      if (at.getScope().contains("email")) {
        builder.addField("email", a.getUserInfo().getEmail());
        builder.addField("email_verified", a.getUserInfo().getEmailVerified());
      }
    }
    return builder.build();
  }

  private void includeIfNotNull(Builder builder, String key, Object value) {

    if (value != null) {
      builder.addField(key, value.toString());
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