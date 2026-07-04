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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;

import it.infn.mw.iam.authn.oidc.OIDCAuthenticationFilter;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.PlainAuthRequestUrlBuilder;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;

@ExtendWith(MockitoExtension.class)
public class OIDCExternalAuthenticationWithPKCE {

  private static final String CODE_VERIFIER_SESSION_VARIABLE = "code_verifier";
  private static final String REDIRECT_URI_SESSION_VARIABLE = "redirect_uri";

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
  private ObjectMapper objectMapper;

  private OIDCAuthenticationFilter filter;


  @BeforeEach
  void setUp() {
    filter = new OIDCAuthenticationFilter(validationServices, issuerService, servers, clients,
        authRequestBuilder, clock, tokenRequestor, env, objectMapper, 60);
  }

  @Test
  void testGeneratePkceChallengeUsingS256() throws Exception {

    MockHttpSession session = new MockHttpSession();
    Map<String, String> options = new HashMap<>();

    filter.addPkceChallenge(session, "S256", options);

    assertEquals("S256", options.get("code_challenge_method"));

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

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.addPkceChallenge(session, "plain", options));

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
  void shouldSendStoredCodeVerifierToTokenEndpoint() {

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

}
