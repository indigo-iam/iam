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
package it.infn.mw.iam.test.ext_authn.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.openid.connect.client.model.IssuerServiceResponse;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.gson.JsonObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationFilter;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationProvider;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.OidcClientError;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.PendingOIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.PlainAuthRequestUrlBuilder;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.authn.oidc.service.OidcAccountProvisioningService;
import it.infn.mw.iam.authn.oidc.service.UserInfoFetcher;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.config.oidc.IamOidcJITAccountProvisioningProperties;
import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@ExtendWith(MockitoExtension.class)
class OIDCAuthenticationFilterTests {

  private static final String CODE_VERIFIER_SESSION_VARIABLE = "code_verifier";
  private static final String REDIRECT_URI_SESSION_VARIABLE = "redirect_uri";
  private static final String ISSUER = "https://issuer.example";

  @Mock
  private JWKSetCacheService validationServices;

  @Mock
  private IssuerService issuerService;

  @Mock
  private OIDCProviderMetadataService servers;

  @Mock
  private OidcProviderProperties clients;

  @Mock
  private PlainAuthRequestUrlBuilder authRequestBuilder;

  @Mock
  private Clock clock;

  @Mock
  private OidcTokenRequestor tokenRequestor;

  @Mock
  private Environment env;

  @Mock
  private AuthenticationValidator<OIDCAuthenticationToken> tokenValidatorService;

  @Mock
  private SessionTimeoutHelper sessionTimeoutHelper;

  @Mock
  private IamAccountRepository accountRepo;

  @Mock
  private InactiveAccountAuthenticationHander inactiveAccountHandler;

  @Mock
  private IamTotpMfaRepository totpMfaRepository;

  @Mock
  private IamOidcJITAccountProvisioningProperties jitProperties;

  @Mock
  private OidcAccountProvisioningService oidcProvisioningService;

  @Mock
  private IamTotpMfaProperties iamTotpMfaProperties;

  @Mock
  private UserInfoFetcher userInfoFetcher;

  private OIDCAuthenticationProvider authProvider;

  private OIDCAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    authProvider = new OIDCAuthenticationProvider(tokenValidatorService, sessionTimeoutHelper,
        accountRepo, inactiveAccountHandler, totpMfaRepository, jitProperties,
        oidcProvisioningService, iamTotpMfaProperties, userInfoFetcher);

    filter = new OIDCAuthenticationFilter(validationServices, issuerService, servers, clients,
        authRequestBuilder, clock, tokenRequestor, env, new ObjectMapper(), 60);
  }

  @Test
  void testThrowExceptionWhenErrorParameterIsPresent() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    request.setParameter("error", "access_denied");
    request.setParameter("error_description", "User denied access");
    request.setParameter("error_uri", ISSUER);

    OidcClientError ex =
        assertThrows(OidcClientError.class, () -> filter.attemptAuthentication(request, response));

    assertEquals("access_denied", ex.getError());
    assertEquals("User denied access", ex.getErrorDescription());
    assertEquals(ISSUER, ex.getErrorUri());
  }

  @Test
  void testThrowExceptionWhenIssuerIsNull() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    when(issuerService.getIssuer(request)).thenReturn(null);

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.attemptAuthentication(request, response));

    assertEquals("Null issuer response returned from service.", ex.getMessage());
  }

  @Test
  void testRedirectWhenRequestIsRedirect() throws Exception {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    IssuerServiceResponse issResp = Mockito.mock(IssuerServiceResponse.class);

    when(issuerService.getIssuer(request)).thenReturn(issResp);
    when(issResp.shouldRedirect()).thenReturn(true);
    when(issResp.getRedirectUrl()).thenReturn(ISSUER + "/login");

    Authentication authentication = filter.attemptAuthentication(request, response);

    assertNull(authentication);
    assertEquals(ISSUER + "/login", response.getRedirectedUrl());
  }

  @Test
  void testThrowExceptionWhenProviderMetadataIsMissing() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("https://client.example/openid_connect_login");

    MockHttpServletResponse response = new MockHttpServletResponse();

    IssuerServiceResponse issResp = Mockito.mock(IssuerServiceResponse.class);

    when(issuerService.getIssuer(request)).thenReturn(issResp);
    when(issResp.shouldRedirect()).thenReturn(false);
    when(issResp.getIssuer()).thenReturn(ISSUER);

    when(servers.load(ISSUER)).thenReturn(null);

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.attemptAuthentication(request, response));

    assertTrue(ex.getMessage().contains("No server configuration found"));
  }

  @Test
  void testThrowExceptionWhenClientConfigurationIsMissing() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("https://client.example/openid_connect_login");

    MockHttpServletResponse response = new MockHttpServletResponse();

    IssuerServiceResponse issResp = Mockito.mock(IssuerServiceResponse.class);

    when(issuerService.getIssuer(request)).thenReturn(issResp);
    when(issResp.shouldRedirect()).thenReturn(false);
    when(issResp.getIssuer()).thenReturn(ISSUER);

    loadOIDCProviderMetadata(ISSUER);

    when(clients.getProviders()).thenReturn(Collections.emptyList());

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.attemptAuthentication(request, response));

    assertTrue(ex.getMessage().contains("No client configuration found for issuer: " + ISSUER));
  }

  @Test
  void testThrowExceptionWhenRedirectUriDoesNotMatchRequest() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("https://wrong.example/openid_connect_login");

    MockHttpServletResponse response = new MockHttpServletResponse();

    IssuerServiceResponse issResp = Mockito.mock(IssuerServiceResponse.class);

    when(issuerService.getIssuer(request)).thenReturn(issResp);
    when(issResp.shouldRedirect()).thenReturn(false);
    when(issResp.getIssuer()).thenReturn(ISSUER);

    loadOIDCProviderMetadata(ISSUER);

    OidcProvider provider = Mockito.mock(OidcProvider.class);
    OidcClient client = new OidcClient("client", "secret",
        "https://expected.example/openid_connect_login", null, null, null, null);

    when(provider.getIssuer()).thenReturn(ISSUER);
    when(provider.getClient()).thenReturn(client);
    when(clients.getProviders()).thenReturn(List.of(provider));

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.attemptAuthentication(request, response));
    assertTrue(ex.getMessage().contains("RequestURI mismatch."));

    client = new OidcClient("client", "secret", null, null, null, null, null);
    when(provider.getClient()).thenReturn(client);
    when(clients.getProviders()).thenReturn(List.of(provider));

    ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.attemptAuthentication(request, response));
    assertTrue(ex.getMessage().contains("RequestURI mismatch."));
  }

  @Test
  void testUseAcrValuesFromRequestParameter() throws Exception {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpSession session = new MockHttpSession();

    request.setParameter("acr_values", "acr1 acr2");

    Map<String, String> options = new HashMap<>();

    filter.populateAcrOptions(session, request, options);

    assertEquals("acr1 acr2", options.get("acr_values"));
  }

  @Test
  void testExtractAcrValuesFromClaimsJson() throws Exception {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpSession session = new MockHttpSession();
    ObjectMapper mapper = new ObjectMapper();

    ObjectNode claims = mapper.createObjectNode();

    ObjectNode idToken = mapper.createObjectNode();
    ObjectNode acr = mapper.createObjectNode();
    ArrayNode values = mapper.createArrayNode();

    values.add("acr1");
    values.add("acr2");

    acr.set("values", values);
    idToken.set("acr", acr);
    claims.set("id_token", idToken);

    request.setParameter("claims", mapper.writeValueAsString(claims));

    Map<String, String> options = new HashMap<>();

    filter.populateAcrOptions(session, request, options);

    assertEquals("acr1 acr2", options.get("acr_values"));
    assertEquals("acr1 acr2", session.getAttribute("acr_values"));
  }

  @Test
  void testdUseMfaDefaultWhenNoAcrAndNoClaims() throws JsonProcessingException {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpSession session = new MockHttpSession();

    when(env.getActiveProfiles()).thenReturn(new String[] {"mfa"});

    Map<String, String> options = new HashMap<>();

    filter.populateAcrOptions(session, request, options);

    assertEquals("https://refeds.org/profile/mfa", options.get("acr_values"));
  }

  @Test
  void testNotAddAcrValuesWhenNothingProvided() throws JsonProcessingException {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpSession session = new MockHttpSession();

    when(env.getActiveProfiles()).thenReturn(new String[] {});

    Map<String, String> options = new HashMap<>();

    filter.populateAcrOptions(session, request, options);

    assertTrue(options.isEmpty());
  }

  @Test
  void testGeneratePkceChallengeUsingS256() throws Exception {

    MockHttpSession session = new MockHttpSession();
    Map<String, String> options = new HashMap<>();

    filter.addPkceChallenge(session, PKCEAlgorithm.S256.getName(), options);

    assertEquals(PKCEAlgorithm.S256.getName(), options.get("code_challenge_method"));

    String verifier = (String) session.getAttribute(CODE_VERIFIER_SESSION_VARIABLE);
    assertNotNull(verifier);

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    String expected =
        Base64URL.encode(digest.digest(verifier.getBytes(StandardCharsets.US_ASCII))).toString();

    assertEquals(expected, options.get("code_challenge"));
  }

  @Test
  void testRejectPlainPkceMethod() {

    MockHttpSession session = new MockHttpSession();
    Map<String, String> options = new HashMap<>();

    String algorithm = PKCEAlgorithm.plain.getName();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.addPkceChallenge(session, algorithm, options));

    assertTrue(ex.getMessage().contains("Expected S256"));
  }

  @Test
  void testNotGeneratePkceWhenMethodIsNull() {

    MockHttpSession session = new MockHttpSession();

    Map<String, String> options = new HashMap<>();

    filter.addPkceChallenge(session, null, options);

    assertTrue(options.isEmpty());
    assertNull(session.getAttribute(CODE_VERIFIER_SESSION_VARIABLE));
  }

  @Test
  void testSendStoredCodeVerifierToTokenEndpoint() {

    MockHttpServletRequest request = new MockHttpServletRequest();

    request.setParameter("code", "abc");

    MockHttpSession session = new MockHttpSession();

    session.setAttribute(CODE_VERIFIER_SESSION_VARIABLE, "myVerifier");
    session.setAttribute(REDIRECT_URI_SESSION_VARIABLE, "https://test.example/callback");

    request.setSession(session);

    MultiValueMap<String, String> params = filter.initTokenRequestParameters(request);

    assertEquals("authorization_code", params.getFirst("grant_type"));
    assertEquals("abc", params.getFirst("code"));
    assertEquals("myVerifier", params.getFirst("code_verifier"));
    assertEquals("https://test.example/callback", params.getFirst("redirect_uri"));
  }

  @Test
  void testThrowExceptionWhenStateDoesNotMatch() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpSession session = new MockHttpSession();

    session.setAttribute("state", "expected");
    request.setSession(session);
    request.setParameter("state", "received");

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.handleAuthorizationCodeResponse(request));

    assertTrue(ex.getMessage().contains("State parameter mismatch"));
  }

  @Test
  void testThrowExceptionWhenIssuerIsMissingFromSession() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpSession session = new MockHttpSession();

    session.setAttribute("state", "1234");
    request.setSession(session);

    request.setParameter("state", "1234");

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.handleAuthorizationCodeResponse(request));

    assertEquals("Issuer not found in session.", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenTokenResponseDoesNotContainAccessToken() {

    MockHttpServletRequest request = createAuthorizationCodeRequest(ISSUER);

    OIDCProviderMetadata metadata = loadOIDCProviderMetadata(ISSUER);

    OidcProvider provider = Mockito.mock(OidcProvider.class);
    OidcClient client = new OidcClient("client", "secret", ISSUER + "/openid_connect_login", null,
        null, null, null);

    when(provider.getIssuer()).thenReturn(ISSUER);
    when(provider.getClient()).thenReturn(client);
    when(clients.getProviders()).thenReturn(List.of(provider));

    ObjectNode node = new ObjectMapper().createObjectNode();
    node.put("id_token", "dummy");
    when(tokenRequestor.requestTokens(eq(metadata.tokenEndpoint()), eq(client), any()))
      .thenReturn(node.toString());

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.handleAuthorizationCodeResponse(request));

    assertTrue(ex.getMessage().contains("access_token"));
  }

  @Test
  void testThrowExceptionWhenTokenResponseDoesNotContainIdToken() {

    MockHttpServletRequest request = createAuthorizationCodeRequest(ISSUER);

    OIDCProviderMetadata metadata = loadOIDCProviderMetadata(ISSUER);
    when(servers.load(ISSUER)).thenReturn(metadata);

    OidcProvider provider = Mockito.mock(OidcProvider.class);
    OidcClient client = new OidcClient("client", "secret", ISSUER + "/openid_connect_login", null,
        null, null, null);

    when(provider.getIssuer()).thenReturn(ISSUER);
    when(provider.getClient()).thenReturn(client);

    when(clients.getProviders()).thenReturn(List.of(provider));

    ObjectNode node = new ObjectMapper().createObjectNode();
    node.put("access_token", "dummy");
    when(tokenRequestor.requestTokens(eq(metadata.tokenEndpoint()), eq(client), any()))
      .thenReturn(node.toString());

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.handleAuthorizationCodeResponse(request));

    assertEquals("Token Endpoint did not return an id_token", ex.getMessage());
  }

  @Test
  void testAuthenticateReturnsNullWhenAuthenticationIsNotSupported() {

    Authentication unsupportedAuthentication =
        new UsernamePasswordAuthenticationToken("user", "password");

    Authentication result = authProvider.authenticate(unsupportedAuthentication);

    assertNull(result);
  }

  @Test
  void testAuthenticationFailsWhenUserInfoSubjectDoesNotMatchTokenSubject() {

    PendingOIDCAuthenticationToken pendingToken =
        Mockito.mock(PendingOIDCAuthenticationToken.class);

    UserInfo userInfo = Mockito.mock(UserInfo.class);

    when(pendingToken.getSub()).thenReturn("token-sub");
    when(userInfo.getSub()).thenReturn("userinfo-sub");
    when(userInfoFetcher.loadUserInfo(pendingToken)).thenReturn(Optional.of(userInfo));

    assertThrows(AuthenticationServiceException.class,
        () -> authProvider.authenticate(pendingToken));
  }

  @Test
  void testJitProvisioningCreatesNewAccount() throws ParseException {

    PendingOIDCAuthenticationToken pendingToken = buildPendingToken("1234");
    UserInfo userInfo = buildUserInfo();

    when(userInfoFetcher.loadUserInfo(pendingToken)).thenReturn(Optional.of(userInfo));
    when(accountRepo.findByOidcId(anyString(), anyString())).thenReturn(Optional.empty());
    when(jitProperties.getEnabled()).thenReturn(true);

    IamAccount account = Mockito.mock(IamAccount.class);
    when(oidcProvisioningService.provisionAccount(any())).thenReturn(account);

    when(sessionTimeoutHelper.getDefaultSessionExpirationTime())
      .thenReturn(Instant.now().plusSeconds(3600));

    Authentication result = authProvider.authenticate(pendingToken);

    assertNotNull(result);
    verify(oidcProvisioningService).provisionAccount(any());
  }

  @Test
  void testUnregisteredAuthenticationWhenJitDisabled() throws ParseException {

    PendingOIDCAuthenticationToken pendingToken = buildPendingToken("1234");
    UserInfo userInfo = Mockito.mock(UserInfo.class);
    when(userInfo.getSub()).thenReturn("1234");
    when(userInfoFetcher.loadUserInfo(pendingToken)).thenReturn(Optional.of(userInfo));
    when(accountRepo.findByOidcId(anyString(), anyString())).thenReturn(Optional.empty());
    when(jitProperties.getEnabled()).thenReturn(false);
    when(sessionTimeoutHelper.getDefaultSessionExpirationTime())
      .thenReturn(Instant.now().plusSeconds(3600));

    Authentication result = authProvider.authenticate(pendingToken);

    assertNotNull(result);
    verifyNoInteractions(oidcProvisioningService);
  }

  @Test
  void testUnregisteredAuthenticationFailsWhenUserInfoIsInvalid() throws ParseException {

    PendingOIDCAuthenticationToken pendingToken = buildPendingToken("1234");
    UserInfo userInfo = Mockito.mock(UserInfo.class);
    when(userInfo.getSub()).thenReturn(null);
    when(userInfoFetcher.loadUserInfo(pendingToken)).thenReturn(Optional.of(userInfo));

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> authProvider.authenticate(pendingToken));

    assertEquals("Authentication failed: invalid subject", ex.getMessage());
  }

  @Test
  void testComputeAcrValueHandlesParseException() throws Exception {

    OIDCAuthenticationToken token = Mockito.mock(OIDCAuthenticationToken.class);
    JWT jwt = Mockito.mock(JWT.class);

    when(token.getIdToken()).thenReturn(jwt);
    when(jwt.getJWTClaimsSet()).thenThrow(new ParseException("invalid jwt", 0));

    String acr = invokeComputeAcrValue(token);

    assertNull(acr);
  }

  @Test
  void testUnregisteredUserUsesUserInfoNameAsUsername() throws ParseException {

    PendingOIDCAuthenticationToken pendingToken = buildPendingToken("1234");

    UserInfo userInfo = Mockito.mock(UserInfo.class);
    when(userInfo.getSub()).thenReturn("1234");

    when(userInfoFetcher.loadUserInfo(pendingToken)).thenReturn(Optional.of(userInfo));
    when(userInfo.getName()).thenReturn("Test");
    when(accountRepo.findByOidcId(anyString(), anyString())).thenReturn(Optional.empty());
    when(jitProperties.getEnabled()).thenReturn(false);
    when(sessionTimeoutHelper.getDefaultSessionExpirationTime())
      .thenReturn(Instant.now().plusSeconds(3600));

    Authentication result = authProvider.authenticate(pendingToken);

    OidcExternalAuthenticationToken external = (OidcExternalAuthenticationToken) result;

    assertEquals("Test", external.getName());
  }

  private OIDCProviderMetadata loadOIDCProviderMetadata(String issuer) {

    ObjectNode raw = new ObjectMapper().createObjectNode();
    OIDCProviderMetadata metadata = new OIDCProviderMetadata(issuer, issuer + "/authorize",
        issuer + "/token", issuer + "/jwks", issuer + "/userinfo", raw);
    when(servers.load(issuer)).thenReturn(metadata);

    return metadata;
  }

  private String invokeComputeAcrValue(OIDCAuthenticationToken token) throws Exception {

    Method method = OIDCAuthenticationProvider.class.getDeclaredMethod("computeAcrValue",
        OIDCAuthenticationToken.class);

    method.setAccessible(true);

    return (String) method.invoke(authProvider, token);
  }

  private PendingOIDCAuthenticationToken buildPendingToken(String subject) throws ParseException {

    JWT idToken = Mockito.mock(JWT.class);
    lenient().when(idToken.getJWTClaimsSet())
      .thenReturn(new JWTClaimsSet.Builder().subject(subject).issuer(ISSUER).build());

    OIDCProviderMetadata metadata =
        new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize", ISSUER + "/token", ISSUER + "/jwks",
            ISSUER + "/userinfo", new ObjectMapper().createObjectNode());

    return new PendingOIDCAuthenticationToken("1234", ISSUER, metadata, idToken, "access-token");
  }

  private MockHttpServletRequest createAuthorizationCodeRequest(String issuer) {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpSession session = new MockHttpSession();

    session.setAttribute("state", "1234");
    session.setAttribute("issuer", issuer);

    request.setSession(session);
    request.setParameter("state", "1234");
    request.setParameter("code", "5678");

    return request;
  }

  private UserInfo buildUserInfo() {

    JsonObject json = new JsonObject();
    json.addProperty("sub", "1234");
    json.addProperty("name", "Test");

    return DefaultUserInfo.fromJson(json);
  }
}
