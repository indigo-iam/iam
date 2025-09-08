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

import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.AUD;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.EXP;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.IAT;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.ISS;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.JTI;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.NBF;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.SCOPE;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.SUB;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.USERNAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL_VERIFIED;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.FAMILY_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.GIVEN_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.MIDDLE_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NICKNAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PICTURE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PREFERRED_USERNAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.UPDATED_AT;

import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;

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
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
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

  private static final Logger LOG = LoggerFactory.getLogger(IamIntrospectionEndpoint.class);

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
      Authentication auth)
      throws UnauthorizedClientException, ParseException, InvalidTokenException {

    ClientDetailsEntity authenticatedClient = loadClient(auth);
    validate(authenticatedClient, tokenValue);
    JWT jwt = JWTParser.parse(tokenValue);
    if (jwt instanceof PlainJWT refreshToken) {
      // It's a RefreshToken
      return introspectRefreshToken(refreshToken);
    }
    if (jwt instanceof SignedJWT accessToken) {
      // It's an AccessToken
      return introspectAccessToken(accessToken);
    }
    throw new InvalidTokenException("Expected a SignedJWT or PlainJWT object");
  }

  private void validate(ClientDetailsEntity c, String tokenValue)
      throws UnauthorizedClientException, InvalidTokenException {

    // check if client has been suspended
    if (!c.isActive()) {
      String errorMsg = String.format(SUSPENDED_CLIENT_ERROR, c.getClientId());
      LOG.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }

    // check if client is allowed to introspect tokens
    if (!c.isAllowIntrospection()) {
      String errorMsg = String.format(NOT_ALLOWED_CLIENT_ERROR, c.getClientId());
      LOG.error(errorMsg);
      throw new UnauthorizedClientException(errorMsg);
    }

    // invalid null token to introspect
    if (Strings.isNullOrEmpty(tokenValue)) {
      String errorMsg = "Verify failed; token value is null";
      LOG.error(errorMsg);
      throw new InvalidTokenException(errorMsg);
    }
  }

  private IntrospectionResponse introspectRefreshToken(PlainJWT token)
      throws ParseException, InvalidTokenException {

    OAuth2RefreshTokenEntity rt = tokenService.getRefreshToken(token.serialize());
    if (rt.isExpired() || isRevoked(rt) || notYetValid(rt.getJwt())) {
      return IntrospectionResponse.inactive();
    }
    ClientDetailsEntity client = rt.getClient();
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    builder.addField(TOKEN_TYPE, TokenTypeHint.REFRESH_TOKEN);
    builder.addField(SUB, rt.getJwt().getJWTClaimsSet().getSubject());
    includeIfNotNull(builder, EXP, rt.getExpiration());
    builder.addField(CLIENT_ID, client.getClientId());
    includeIfNotNull(builder, "client_name", client.getClientName());
    includeIfNotNull(builder, "client_last_used", client.getClientLastUsed());
    // add all the others avoiding duplicates/override
    rt.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addFieldIfAbsent);
    return builder.build();
  }

  private IntrospectionResponse introspectAccessToken(SignedJWT token)
      throws InvalidTokenException, ParseException {

    OAuth2AccessTokenEntity at = tokenService.readAccessToken(token.serialize());
    if (at.isExpired() || isRevoked(at) || notYetValid(at.getJwt())) {
      return IntrospectionResponse.inactive();
    }
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);
    builder.addField(TOKEN_TYPE, TokenTypeHint.ACCESS_TOKEN);
    String subject = at.getJwt().getJWTClaimsSet().getSubject();
    ClientDetailsEntity client = at.getClient();
    builder.addField(SUB, subject);
    builder.addField(CLIENT_ID, client.getClientId());
    includeIfNotNull(builder, "client_name", client.getClientName());
    includeIfNotNull(builder, "client_last_used", client.getClientLastUsed());
    includeIfNotNull(builder, EXP, at.getExpiration());
    builder.addField(IAT, at.getJwt().getJWTClaimsSet().getIssueTime());
    builder.addField(ISS, at.getJwt().getJWTClaimsSet().getIssuer());
    builder.addField(JTI, at.getJwt().getJWTClaimsSet().getJWTID());
    includeIfNotNull(builder, NBF, at.getJwt().getJWTClaimsSet().getNotBeforeTime());
    includeIfNotEmpty(builder, AUD, at.getJwt().getJWTClaimsSet().getAudience());
    includeIfNotEmpty(builder, SCOPE, at.getScope());

    if (!client.getClientId().equals(subject)) {
      IamAccount a = accountService.findByUuid(subject)
        .orElseThrow(
            () -> new IllegalStateException("Token sub doesn't refer to any registered user"));
      builder.addField(USERNAME, a.getUsername());
      // backward compatibility
      builder.addField("user_id", a.getUsername());
      if (at.getScope().contains(OidcScopes.PROFILE)) {
        includeIfNotNull(builder, GIVEN_NAME, a.getUserInfo().getGivenName());
        includeIfNotNull(builder, MIDDLE_NAME, a.getUserInfo().getMiddleName());
        includeIfNotNull(builder, FAMILY_NAME, a.getUserInfo().getFamilyName());
        includeIfNotNull(builder, NAME, a.getUserInfo().getName());
        includeIfNotNull(builder, NICKNAME, a.getUserInfo().getNickname());
        includeIfNotNull(builder, PICTURE, a.getUserInfo().getPicture());
        includeIfNotNull(builder, "affiliation", a.getUserInfo().getAffiliation());
        includeIfNotNull(builder, PREFERRED_USERNAME, a.getUserInfo().getPreferredUsername());
        includeIfNotNull(builder, UPDATED_AT, a.getLastUpdateTime());
        includeIfNotNull(builder, "last_login_at", a.getLastLoginTime());
      }
      if (at.getScope().contains(OidcScopes.EMAIL)) {
        builder.addField(EMAIL, a.getUserInfo().getEmail());
        builder.addField(EMAIL_VERIFIED, a.getUserInfo().getEmailVerified());
      }
    }
    // add all the others avoiding duplicates/override
    at.getJwt().getJWTClaimsSet().getClaims().forEach(builder::addFieldIfAbsent);
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

  private boolean notYetValid(JWT jwt) throws ParseException {

    Optional<Date> notBefore = Optional.ofNullable(jwt.getJWTClaimsSet().getNotBeforeTime());
    return notBefore.isPresent() && notBefore.get().after(new Date());
  }

  private boolean isRevoked(OAuth2AccessTokenEntity at)
      throws InvalidTokenException, ParseException {

    return revocationService.isAccessTokenRevoked((SignedJWT) at.getJwt());
  }

  private boolean isRevoked(OAuth2RefreshTokenEntity rt)
      throws InvalidTokenException, ParseException {

    return revocationService.isRefreshTokenRevoked((PlainJWT) rt.getJwt());
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
