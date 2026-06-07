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
package it.infn.mw.iam.test.util;

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.api.tokens.TokensControllerSupport.APPLICATION_JSON_CONTENT_TYPE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.tomcat.util.buf.StringUtils;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.GrantType;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.tokens.Constants;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
public class TokenGetterUtils implements StructuredScopeTestSupportConstants {

  protected static final String REFRESH_TOKENS_BASE_PATH = Constants.REFRESH_TOKENS_ENDPOINT;
  protected static final String ACCESS_TOKENS_BASE_PATH = Constants.ACCESS_TOKENS_ENDPOINT;

  @Autowired
  protected ObjectMapper mapper;

  @Autowired
  protected MockMvc mvc;

  // Password Flow

  protected TokenEndpointResponse getPasswordTokenResponse(String scopes) throws Exception {

    return parseTokens(getPasswordTokenResponse(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET,
        TEST_USERNAME, TEST_PASSWORD, scopes, null));
  }

  protected DefaultOAuth2AccessToken getPasswordTokenResponse(String clientId, String clientSecret,
      String username, String password, String scope, String audience) throws Exception {

    return new AccessTokenGetter().grantType("password")
      .clientId(clientId)
      .clientSecret(clientSecret)
      .username(username)
      .password(password)
      .scope(scope)
      .audience(audience)
      .getTokenResponseObject();
  }

  protected TokenEndpointResponse getPasswordToken() throws Exception {

    return getPasswordToken(EMPTY_SCOPES);
  }

  protected TokenEndpointResponse parseTokens(DefaultOAuth2AccessToken response) {

    String accessToken = response.getValue();
    String refreshToken = Optional.ofNullable(response.getRefreshToken())
      .map(OAuth2RefreshToken::getValue)
      .orElse(null);
    String idToken = (String) response.getAdditionalInformation().get("id_token");
    return new TokenEndpointResponse(accessToken, refreshToken, idToken);
  }

  protected TokenEndpointResponse getPasswordToken(String clientId, String clientSecret,
      String username, String password, String scopes) throws Exception {

    return parseTokens(
        getPasswordTokenResponse(clientId, clientSecret, username, password, scopes, clientId));
  }

  protected TokenEndpointResponse getPasswordToken(String scopes) throws Exception {

    return getPasswordToken(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET, TEST_USERNAME,
        TEST_PASSWORD, scopes);
  }

  protected TokenEndpointResponse getPasswordToken(Set<String> scopes) throws Exception {

    return parseTokens(getPasswordTokenResponse(PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET,
        TEST_USERNAME, TEST_PASSWORD, StringUtils.join(scopes, ' '), PASSWORD_CLIENT_ID));
  }

  // Client Credentials Flow

  public DefaultOAuth2AccessToken getClientCredentialsTokenResponse(String clientId,
      String clientSecret, String scopes) throws Exception {

    return new AccessTokenGetter().grantType(GrantType.CLIENT_CREDENTIALS.getValue())
      .clientId(clientId)
      .clientSecret(clientSecret)
      .scope(scopes)
      .getTokenResponseObject();
  }

  protected TokenEndpointResponse getClientCredentialsToken() throws Exception {

    return getClientCredentialsToken(EMPTY_SCOPES);
  }

  protected TokenEndpointResponse getClientCredentialsToken(String scopes) throws Exception {

    return parseTokens(getClientCredentialsTokenResponse(CLIENT_CREDENTIALS_CLIENT_ID,
        CLIENT_CREDENTIALS_CLIENT_SECRET, scopes));
  }

  // Refresh Flow

  protected TokenEndpointResponse getRefreshTokenResponse(String refreshToken, String scopes)
      throws Exception {

    return getRefreshTokenResponse(refreshToken, PASSWORD_CLIENT_ID, PASSWORD_CLIENT_SECRET,
        scopes);
  }

  // Exchange Flow

  protected TokenEndpointResponse getExchangeTokenResponse(String subjectToken, String clientId,
      String clientSecret, String scope, String audience) throws Exception {

    return parseTokens(new AccessTokenGetter().grantType(GrantType.TOKEN_EXCHANGE.getValue())
      .clientId(clientId)
      .clientSecret(clientSecret)
      .subjectToken(subjectToken)
      .scope(scope)
      .audience(audience)
      .getTokenResponseObject());
  }

  protected TokenEndpointResponse getExchangeTokenResponse(String subjectToken, String scope,
      String audience) throws Exception {

    return getExchangeTokenResponse(subjectToken, EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET, scope,
        audience);
  }

  protected TokenEndpointResponse getRefreshTokenResponse(String refreshToken, String clientId,
      String clientSecret, String scopes) throws Exception {

    return parseTokens(new AccessTokenGetter().grantType("refresh_token")
      .clientId(clientId)
      .clientSecret(clientSecret)
      .refreshToken(refreshToken)
      .scope(scopes)
      .getTokenResponseObject());
  }

  public record TokenEndpointResponse(String accessToken, String refreshToken, String idToken) {
  }

  public class AccessTokenGetter {
    private String clientId;
    private String clientSecret;
    private String scope;
    private String grantType;
    private String username;
    private String password;
    private String audience;
    private String resource;
    private String claims;
    private String refreshToken;
    private String subjectToken;

    public AccessTokenGetter clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public AccessTokenGetter clientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public AccessTokenGetter scope(String scope) {
      this.scope = scope;
      return this;
    }

    public AccessTokenGetter grantType(String grantType) {
      this.grantType = grantType;
      return this;
    }

    public AccessTokenGetter username(String username) {
      this.username = username;
      return this;
    }

    public AccessTokenGetter password(String password) {
      this.password = password;
      return this;
    }

    public AccessTokenGetter audience(String audience) {
      this.audience = audience;
      return this;
    }

    public AccessTokenGetter resource(String resource) {
      this.resource = resource;
      return this;
    }

    public AccessTokenGetter claims(String claims) {
      this.claims = claims;
      return this;
    }

    public AccessTokenGetter refreshToken(String refreshToken) {
      this.refreshToken = refreshToken;
      return this;
    }

    public AccessTokenGetter subjectToken(String subjectToken) {
      this.subjectToken = subjectToken;
      return this;
    }

    public String performSuccessfulTokenRequest() throws Exception {

      return performTokenRequest(200).getResponse().getContentAsString();
    }

    public MvcResult performTokenRequest(int statusCode) throws Exception {
      MockHttpServletRequestBuilder req = post("/token").param("grant_type", grantType)
        .param("client_id", clientId)
        .param("client_secret", clientSecret);

      if (!isNullOrEmpty(scope)) {
        req.param("scope", scope);
      }
      final GrantType grant = GrantType.parse(grantType);

      if (GrantType.PASSWORD.equals(grant)) {
        req.param("username", username).param("password", password);
      }

      if (GrantType.REFRESH_TOKEN.equals(grant)) {
        req.param("refresh_token", refreshToken);
      }

      if (GrantType.TOKEN_EXCHANGE.equals(grant)) {
        req.param("subject_token", subjectToken);
      }

      if (audience != null) {
        req.param("aud", audience);
      }

      if (resource != null) {
        req.param("resource", resource);
      }

      if (claims != null) {
        req.param("claims", claims);
      }

      return mvc.perform(req).andExpect(status().is(statusCode)).andReturn();
    }

    public DefaultOAuth2AccessToken getTokenResponseObject() throws Exception {

      String response = performSuccessfulTokenRequest();

      // This is incorrectly named in spring security OAuth, what they call OAuth2AccessToken
      // is a TokenResponse object
      return mapper.readValue(response, DefaultOAuth2AccessToken.class);
    }

    public String getAccessTokenValue() throws Exception {

      return getTokenResponseObject().getValue();
    }
  }

  protected ListAppender<ILoggingEvent> attachLogCaptor(Class<?> clazz) {
    Logger logger = (Logger) org.slf4j.LoggerFactory.getLogger(clazz);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  protected OAuth2Authentication oauth2Authentication(ClientDetailsEntity client, String username,
      String[] scopes) {

    Authentication userAuth = null;
    Map<String, String> requestParameters = new HashMap<String, String>();
    requestParameters.put("grant_type", "authorization_code");

    if (username != null) {
      userAuth = new UsernamePasswordAuthenticationToken(username, "");
    }

    MockOAuth2Request req = new MockOAuth2Request(client.getClientId(), scopes);
    req.setRequestParameters(requestParameters);
    return new OAuth2Authentication(req, userAuth);
  }

  public Authentication anonymousAuthenticationToken() {
    return new AnonymousAuthenticationToken("key", "anonymous",
        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
  }

  protected ListResponseDTO<AccessToken> getAccessTokenList() throws Exception {

    return getAccessTokenList(new LinkedMultiValueMap<String, String>());
  }

  protected ListResponseDTO<AccessToken> getAccessTokenList(MultiValueMap<String, String> params)
      throws Exception {

    /* @formatter:off */
    return mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH)
            .contentType(APPLICATION_JSON_CONTENT_TYPE)
            .params(params))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString(), new TypeReference<ListResponseDTO<AccessToken>>() {});
    /* @formatter:on */
  }

  protected ListResponseDTO<RefreshToken> getRefreshTokenList() throws Exception {

    return getRefreshTokenList(new LinkedMultiValueMap<String, String>());
  }

  protected ListResponseDTO<RefreshToken> getRefreshTokenList(MultiValueMap<String, String> params)
      throws Exception {

    /* @formatter:off */
    return mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH)
            .contentType(APPLICATION_JSON_CONTENT_TYPE)
            .params(params))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString(), new TypeReference<ListResponseDTO<RefreshToken>>() {});
    /* @formatter:on */
  }

  protected ResultActions revoke(String username, String password, String tokenToRevoke)
      throws Exception {

    return mvc.perform(post(REVOCATION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToRevoke));
  }

  protected ResultActions introspect(String username, String password, String tokenToIntrospect,
      TokenTypeHint tokenTypeHint) throws Exception {

    return introspect(username, password, tokenToIntrospect, tokenTypeHint.name());
  }

  protected ResultActions introspect(String username, String password, String tokenToIntrospect,
      String tokenTypeHint) throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint));
  }

  protected ResultActions introspect(String username, String password, String tokenToIntrospect)
      throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect));
  }

  protected ResultActions introspect(String tokenToIntrospect, TokenTypeHint tokenTypeHint)
      throws Exception {

    return introspect(tokenToIntrospect, tokenTypeHint.name());
  }

  protected ResultActions introspect(String tokenToIntrospect, String tokenTypeHint)
      throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(anonymous())
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint));
  }

  protected String buildPlainJwt(String issuer, String subject, String clientId, String scopes, Instant iat) {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer)
      .subject(subject)
      .issueTime(Date.from(iat))
      .expirationTime(Date.from(iat.plusSeconds(3600)))
      .jwtID("jti-external-123")
      .claim("client_id", clientId)
      .claim("scope", scopes)
      .build();

    PlainJWT jwt = new PlainJWT(claims);
    return jwt.serialize();
  }
}
