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
package it.infn.mw.iam.test.openid_federation;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.core.oidc.InvalidTrustChainException;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class AutomaticClientRegistrationTests {

  @Value("${iam.issuer}")
  private String issuer;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamClientRepository clientRepo;

  @MockBean
  private TrustChainService trustChainService;

  @MockBean
  private JWKSetCacheService jwkService;

  private TrustChain fakeChain;

  private RSAKey rsaJWK;

  private JWKSet jwkSet;

  @BeforeEach
  void setup() throws Exception {
    rsaJWK = new RSAKeyGenerator(2048).keyID("rsa1").generate();

    jwkSet = new JWKSet(rsaJWK.toPublicJWK());
    JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);
    JWTSigningAndValidationService validator = new DefaultJWTSigningAndValidationService(keyStore);

    when(jwkService.getValidator(anyString())).thenReturn(validator);
  }

  private String generateRequestJWT(String entityId, String redirectUri, List<String> trustChain)
      throws Exception {
    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(entityId)
      .audience(issuer)
      .issueTime(new Date())
      .jwtID(UUID.randomUUID().toString())
      .expirationTime(Date.from(Instant.now().plusSeconds(300)))
      .claim("client_id", entityId)
      .claim("redirect_uri", redirectUri)
      .claim("trust_chain", trustChain) // optional
      .build();

    SignedJWT signedJWT =
        new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID())
          .type(JOSEObjectType.JWT)
          .build(), claims);

    signedJWT.sign(new RSASSASigner(rsaJWK.toPrivateKey()));

    return signedJWT.serialize();
  }

  private String generateClientAssertion(String clientId, String tokenEndpoint)
      throws JOSEException {
    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(clientId)
      .subject(clientId)
      .audience(tokenEndpoint)
      .jwtID(UUID.randomUUID().toString())
      .issueTime(new Date())
      .expirationTime(Date.from(Instant.now().plusSeconds(300)))
      .build();

    SignedJWT signedJWT = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claims);

    signedJWT.sign(new RSASSASigner(rsaJWK.toPrivateKey()));

    return signedJWT.serialize();
  }

  @Test
  void testAutomaticClientRegistrationWithEntityId() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/callback";
    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, null);

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri),
        jwkSet, null);

    when(trustChainService.validateFromEntityId(rpEntityId)).thenReturn(fakeChain);

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals("http://localhost/login", result.getResponse().getHeader("Location"));

    MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);

    var resultLogin = mvc
      .perform(post("/login").session(session)
        .param("username", "test")
        .param("password", "password")
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertTrue(
        resultLogin.getResponse().getHeader("Location").startsWith("http://localhost/authorize"));

    mvc
      .perform(get("/authorize").session(session)
        .param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isOk());

    var approveResult = mvc
      .perform(post("/authorize").session(session)
        .param("scope.openid", "true")
        .param("remember", "none")
        .param("user_oauth_approval", "true")
        .param("authorize", "Authorize"))
      .andExpect(status().isSeeOther())
      .andExpect(header().exists("Location"))
      .andReturn();

    String authorizeRedirect = approveResult.getResponse().getHeader("Location");
    assertTrue(authorizeRedirect.startsWith(redirectUri));

    String code = UriComponentsBuilder.fromUriString(authorizeRedirect)
      .build()
      .getQueryParams()
      .getFirst("code");

    String clientAssertion = generateClientAssertion(rpEntityId, "http://localhost:8080/token");
    String tokenResponse =
        mvc
          .perform(post("/token").param("grant_type", "authorization_code")
            .param("code", code)
            .param("redirect_uri", redirectUri)
            .param("client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .param("client_assertion", clientAssertion))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString();

    JsonNode json = new ObjectMapper().readTree(tokenResponse);
    assertNotNull(json.get("access_token"));

    Optional<ClientDetailsEntity> client = clientRepo.findByClientId(rpEntityId);
    assertTrue(client.isPresent());
    assertEquals(rpEntityId, client.get().getClientId());
  }

  @Test
  void testAutomaticClientRegistrationWithTrustChain() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri),
        jwkSet, null);

    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    List<EntityStatement> statements = new ArrayList<>();
    statements.add(fakeChain.getLeafSelfStatement());
    statements.addAll(fakeChain.getSuperiorStatements());
    statements.add(taEC);
    List<String> trustChainStrings =
        statements.stream().map(es -> es.getSignedStatement().serialize()).toList();

    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, trustChainStrings);

    when(trustChainService.validateFromProvidedChain(any())).thenReturn(fakeChain);

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals("http://localhost/login", result.getResponse().getHeader("Location"));
  }

  @Test
  void testClientUpdateIfExpired() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri),
        jwkSet, null);

    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    List<EntityStatement> statements = new ArrayList<>();
    statements.add(fakeChain.getLeafSelfStatement());
    statements.addAll(fakeChain.getSuperiorStatements());
    statements.add(taEC);
    List<String> trustChainStrings =
        statements.stream().map(es -> es.getSignedStatement().serialize()).toList();

    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, trustChainStrings);

    when(trustChainService.validateFromProvidedChain(any())).thenReturn(fakeChain);

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals("http://localhost/login", result.getResponse().getHeader("Location"));

    Optional<ClientDetailsEntity> client = clientRepo.findByClientId(rpEntityId);
    assertTrue(client.isPresent());
    client.get().getClientRelyingParty().setExpiration(new Date());
    client.get().setActive(false);

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals("http://localhost/login", result.getResponse().getHeader("Location"));
    client = clientRepo.findByClientId(rpEntityId);
    assertTrue(client.isPresent());
    assertTrue(client.get().isActive());
  }

  @Test
  void testRegistrationWithoutRedirectUri() throws Exception {
    String rpEntityId = "https://rp.example";
    String requestJwt = generateRequestJWT(rpEntityId, null, null);

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, null, jwkSet, null);

    when(trustChainService.validateFromEntityId(rpEntityId)).thenReturn(fakeChain);

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("request", requestJwt))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType("text/html;charset=UTF-8"))
      .andExpect(content().string(containsString("invalid_redirect_uri")))
      .andExpect(content().string(containsString("Missing redirect URIs")));
  }

  @Test
  void testInvalidTrustChainError() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/callback";
    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, null);

    InvalidTrustChainException ex =
        new InvalidTrustChainException("invalid_trust_chain", "Error description");

    when(trustChainService.validateFromEntityId(rpEntityId)).thenThrow(ex);

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType("text/html;charset=UTF-8"))
      .andExpect(content().string(containsString("invalid_trust_chain")));
  }

  @Test
  void testRegistrationWithInvalidJwt() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/callback";
    String requestJwt = "invalid-jwt";

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType("text/html;charset=UTF-8"))
      .andExpect(content().string(containsString("server_error")));
  }

  @Test
  void testRegistrationWithoutRequestObject() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri),
        jwkSet, null);

    when(trustChainService.validateFromProvidedChain(any())).thenReturn(fakeChain);

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals(redirectUri + "?error=invalid_request&error_description=Missing+request+object",
        result.getResponse().getHeader("Location"));
  }

  @Test
  void testMissingJwksAndJwksUriInRpMetadata() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    fakeChain =
        TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri), null, null);

    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    List<EntityStatement> statements = new ArrayList<>();
    statements.add(fakeChain.getLeafSelfStatement());
    statements.addAll(fakeChain.getSuperiorStatements());
    statements.add(taEC);
    List<String> trustChainStrings =
        statements.stream().map(es -> es.getSignedStatement().serialize()).toList();

    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, trustChainStrings);

    when(trustChainService.validateFromProvidedChain(any())).thenReturn(fakeChain);

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType("text/html;charset=UTF-8"))
      .andExpect(content().string(containsString("invalid_client_metadata")))
      .andExpect(content().string(containsString("No JWKS or jwks_uri provided by RP")));
  }

  @Test
  void testUnknownJwksUriInRpMetadata() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri), null,
        new URI(rpEntityId + "/jwk"));

    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    List<EntityStatement> statements = new ArrayList<>();
    statements.add(fakeChain.getLeafSelfStatement());
    statements.addAll(fakeChain.getSuperiorStatements());
    statements.add(taEC);
    List<String> trustChainStrings =
        statements.stream().map(es -> es.getSignedStatement().serialize()).toList();

    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, trustChainStrings);

    when(trustChainService.validateFromProvidedChain(any())).thenReturn(fakeChain);

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType("text/html;charset=UTF-8"))
      .andExpect(content().string(containsString("invalid_client_metadata")))
      .andExpect(content().string(containsString("Unable to fetch JWKS from RP's jwks_uri")));
  }

  @Test
  void testRequestWithClientIdNotCompliant() throws Exception {
    String rpEntityId = "https://rp.example?foo=x";
    String redirectUri = "https://rp.example/cb";

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals(
        redirectUri + "?error=invalid_request&error_description=Entity+ID+URL+is+not+compliant",
        result.getResponse().getHeader("Location"));
  }

  @Test
  void testRequestWithMalformedClientId() throws Exception {
    String rpEntityId = "https://rp.example:ABC";
    String redirectUri = "https://rp.example/cb";

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals(redirectUri + "?error=invalid_request&error_description=Malformed+Entity+ID+URL",
        result.getResponse().getHeader("Location"));
  }

  @Test
  void testRequestWithClientIdNotFound() throws Exception {
    String rpEntityId = "ht!tps://rp.example";
    String redirectUri = "https://rp.example/cb";

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType("text/html;charset=UTF-8"))
      .andExpect(content().string(containsString("invalid_client")))
      .andExpect(content().string(containsString("Unknown client")));
  }

  @Test
  void testPromptNoneUnauthenticated() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, null);

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri),
        jwkSet, null);

    when(trustChainService.validateFromEntityId(rpEntityId)).thenReturn(fakeChain);

    mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("prompt", "none")
        .param("request", requestJwt))
      .andExpect(status().isFound())
      .andExpect(header().string("Location", containsString("error=login_required")));
  }

  @Test
  void testPromptLoginClearsAuth() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, null);

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri),
        jwkSet, null);

    when(trustChainService.validateFromEntityId(rpEntityId)).thenReturn(fakeChain);

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("prompt", "login")
        .param("request", requestJwt))
      .andReturn();

    MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);

    mvc
      .perform(post("/login").session(session)
        .param("username", "test")
        .param("password", "password")
        .param("submit", "Login"))
      .andExpect(status().isFound());

    // Second request should log user out again because prompt=login ALWAYS forces re-auth
    mvc
      .perform(get("/authorize").session(session)
        .param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("prompt", "login")
        .param("request", requestJwt))
      .andExpect(status().isFound())
      .andExpect(header().string("Location", "http://localhost/login"));
  }

  @Test
  void testMaxAgeForcesLogout() throws Exception {
    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, null);

    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, URI.create(redirectUri),
        jwkSet, null);

    when(trustChainService.validateFromEntityId(rpEntityId)).thenReturn(fakeChain);

    var result = mvc
      .perform(get("/authorize").param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("request", requestJwt))
      .andReturn();

    MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);

    mvc
      .perform(post("/login").session(session)
        .param("username", "test")
        .param("password", "password")
        .param("submit", "Login"))
      .andExpect(status().isFound());

    // Simulate "old" authentication timestamp
    session.setAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP,
        new Date(System.currentTimeMillis() - 10000)); // > 5 seconds ago

    mvc
      .perform(get("/authorize").session(session)
        .param("client_id", rpEntityId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", redirectUri)
        .param("max_age", "5")
        .param("request", requestJwt))
      .andExpect(status().isFound())
      .andExpect(header().string("Location", containsString("/login")));
  }
}
