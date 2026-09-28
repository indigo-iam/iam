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

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.core.oidc.FederationException;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.model.IamFederatedClientEntity;
import it.infn.mw.iam.persistence.repository.IamFederatedClientRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
// @formatter:off
@SpringBootTest(
  classes = {
    IamLoginService.class,
    FederatedOpRegistrationServiceTests.TestConfig.class,
    ClockConfig.class },
  webEnvironment = SpringBootTest.WebEnvironment.MOCK,
  properties = {
    "openid-federation.trust-anchors=https://ta1.example.com,https://ta2.example.com",
    "openid-federation.entity-configuration.authority-hints=https://ta1.example.com,https://auth-hint.example.com"})
//@formatter:on
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
class FederatedOpRegistrationServiceTests {

  private static final String FEDERATED_CLIENT_ID = "federated-client";
  private static final String ISS = "https://op.example.com/";
  private static final String SUB = "http://localhost:8080/";
  private static final String AUD = "http://localhost:8080/";
  private static final String TA = "https://ta1.example.com";

  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    RestTemplateFactory mockRestTemplateFactory() {
      return new MockRestTemplateFactory();
    }
  }

  @Autowired
  MutableClock clock;

  @Autowired
  MockMvc mvc;

  @Autowired
  IamFederatedClientRepository federatedClientRepo;

  @Autowired
  MockRestTemplateFactory mockRtf;

  @MockBean
  TrustChainService trustChainService;

  @MockBean
  OIDCProviderMetadataService metadataService;

  @BeforeEach
  void setup() {

    federatedClientRepo.deleteAll();
    mockRtf.resetServer();
    when(metadataService.load(ISS)).thenReturn(new OIDCProviderMetadata(ISS, ISS + "authorize",
        ISS + "token", ISS + "jwks", ISS + "userinfo"));
  }

  private Date initTrustChain(Clock clock, String iss, URI jwksUri, String ta)
      throws JOSEException, FederationException {

    TrustChain trustChain = TrustChainTestFactory.createOpToTaChain(clock, iss, null, jwksUri, ta);
    when(trustChainService.validateFromEntityId(iss)).thenReturn(trustChain);
    return trustChain.resolveExpirationTime();
  }

  @Test
  void testRpRegistration() throws Exception {
    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    String rpJwt = opJwtResponse(ISS, SUB, iat, exp, AUD, TA);

    mockRtf.getMockServer()
      .expect(requestTo(ISS + "fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess(rpJwt, MediaType.APPLICATION_JSON));

    mvc.perform(get("/openid_connect_login?iss=" + ISS)).andExpect(status().isFound());

    Optional<IamFederatedClientEntity> federatedClient = federatedClientRepo.findByEntityId(ISS);
    assertTrue(federatedClient.isPresent());
    assertEquals("OIDFed remote client", federatedClient.get().getClientName());
  }

  @Test
  void testRpRegistrationFailsWhenNoAuthorityHintsLeadToTA() throws Exception {

    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    String rpJwt = opJwtResponse(ISS, SUB, iat, exp, AUD, TA);

    mockRtf.getMockServer()
      .expect(requestTo(ISS + "fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess(rpJwt, MediaType.APPLICATION_JSON));

    initTrustChain(clock, ISS, URI.create("https://op.example.com/jwk"), "https://ta.example.com");

    TrustChain hintTrustChain = TrustChainTestFactory.createOpToTaChain(clock, ISS, null,
        URI.create("https://op.example.com/jwk"), "https://ta1.example.com");
    when(trustChainService.validateFromEntityId("https://ta1.example.com"))
      .thenReturn(hintTrustChain);

    MvcResult result = mvc.perform(get("/openid_connect_login?iss=" + ISS))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/login?error=true"))
      .andReturn();

    AuthenticationServiceException ex = (AuthenticationServiceException) result.getRequest()
      .getSession()
      .getAttribute(EXT_AUTH_ERROR_KEY);

    assertEquals("Unable to register federated OP: " + ISS, ex.getMessage());
  }

  @Test
  void testRegisteredRpRedirectsToAuthorize() throws Exception {
    Date clientCreatedAt = Date.from(clock.instant());
    Date clientExp = Date.from(clock.instant().plus(1, ChronoUnit.DAYS));
    IamFederatedClientEntity client = createFederatedClient(clientCreatedAt, clientExp);
    federatedClientRepo.save(client);

    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    String rpJwt = opJwtResponse(ISS, SUB, iat, exp, AUD, TA);

    mockRtf.getMockServer()
      .expect(requestTo(ISS + "fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess(rpJwt, MediaType.APPLICATION_JSON));

    mvc.perform(get("/openid_connect_login?iss=" + ISS))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern("https://op.example.com/authorize*"));
  }

  @Test
  void testRpRegistrationHttpError() throws Exception {
    initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    mockRtf.getMockServer()
      .expect(requestTo("https://op.example.com/fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withStatus(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON)
        .body("Something went wrong"));

    mvc.perform(get("/openid_connect_login?iss=" + ISS))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern("/login?error=true"));
  }

  @Test
  void testExpiredOpIsDeletedAndRegisteredAgain() throws Exception {

    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");
    String rpJwt = opJwtResponse(ISS, SUB, iat, exp, AUD, TA);
    mockRtf.getMockServer()
      .expect(requestTo(ISS + "fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess(rpJwt, MediaType.APPLICATION_JSON));

    mvc.perform(get("/openid_connect_login?iss=" + ISS)).andExpect(status().isFound());

    Optional<IamFederatedClientEntity> createdClient = federatedClientRepo.findByEntityId(ISS);
    assertTrue(createdClient.isPresent());
    assertEquals(ISS, createdClient.get().getEntityId());
    assertEquals(exp, createdClient.get().getExpiration());

    clock.advance(Duration.ofDays(2));
    mockRtf.resetServer();

    Date newIat = Date.from(clock.instant());
    Date newExp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");
    String newRpJwt = opJwtResponse(ISS, SUB, newIat, newExp, AUD, TA);
    mockRtf.getMockServer()
      .expect(requestTo(ISS + "fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess(newRpJwt, MediaType.APPLICATION_JSON));

    mvc.perform(get("/openid_connect_login?iss=" + ISS)).andExpect(status().isFound());

    Optional<IamFederatedClientEntity> renewedClient = federatedClientRepo.findByEntityId(ISS);
    assertTrue(renewedClient.isPresent());
    assertEquals(ISS, renewedClient.get().getEntityId());
    assertEquals(newExp, renewedClient.get().getExpiration());

    assertNotEquals(createdClient.get().getId(), renewedClient.get().getId());
  }

  @Test
  void testOpResponseParsingFailure() throws Exception {
    initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    mockRtf.getMockServer()
      .expect(requestTo("https://op.example.com/fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess("fake-jwt", MediaType.APPLICATION_JSON));

    mvc.perform(get("/openid_connect_login?iss=" + ISS))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern("/login?error=true"));
  }

  @Test
  void testIatSetInFutureInOpResponse() throws Exception {
    Instant tomorrowInstant = clock.instant().plus(1, ChronoUnit.DAYS);
    Date iat = Date.from(tomorrowInstant);
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    performCall(ISS, SUB, iat, exp, AUD, TA);
  }

  @Test
  void testExpiredOpResponse() throws Exception {
    Date iat = Date.from(clock.instant());
    Instant yesterdayInstant = clock.instant().minus(1, ChronoUnit.DAYS);
    Date yesterday = Date.from(yesterdayInstant);
    initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    performCall(ISS, SUB, iat, yesterday, AUD, TA);
  }

  @Test
  void testNoAudienceInOpResponse() throws Exception {
    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    performCall(ISS, SUB, iat, exp, null, TA);
  }

  @Test
  void testInvalidAudienceInOpResponse() throws Exception {
    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");
    String aud = "invalid-aud";

    performCall(ISS, SUB, iat, exp, aud, TA);
  }

  @Test
  void testInvalidIssuerInOpResponse() throws Exception {
    String iss = "https://wrong-op.example.com";
    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    performCall(iss, SUB, iat, exp, AUD, TA);
  }

  @Test
  void testInvalidSubjectInOpResponse() throws Exception {
    String sub = "http://wrong-sub.com";
    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");

    performCall(ISS, sub, iat, exp, AUD, TA);
  }

  @Test
  void testInvalidTrustAnchorInOpResponse() throws Exception {
    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");
    String ta = "https://ta.example.com";

    performCall(ISS, SUB, iat, exp, AUD, ta);
  }

  @Test
  void testAuthorityHintsDontLeadToTAPresentInOpResponse() throws Exception {
    Date iat = Date.from(clock.instant());
    Date exp = initTrustChain(clock, ISS, URI.create(ISS + "/jwk"), "https://ta1.example.com");
    String ta = "https://ta2.example.com";

    performCall(ISS, SUB, iat, exp, AUD, ta);
  }

  private IamFederatedClientEntity createFederatedClient(Date createdAt, Date exp) {
    IamFederatedClientEntity client = new IamFederatedClientEntity();
    client.setActive(true);
    client.setClientId(FEDERATED_CLIENT_ID);
    client.setClientSecret("secret");
    client.setClientName("Remote OP");
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic.name());
    client.setJwksUri(ISS + "jwk");
    client.setEntityId(ISS);
    client.setExpiration(exp);
    client.setRedirectUris(Set.of("http://localhost/openid_connect_login"));
    client.setGrantTypes(Set.of("code"));
    client.setResponseTypes(Set.of("code"));
    client.setScope(Set.of("openid"));
    client.setCreatedAt(createdAt);
    return client;
  }

  private String opJwtResponse(String iss, String sub, Date iat, Date exp, String aud, String ta)
      throws JOSEException {
    String clientId = "registered-client";
    String clientSecret = "secret";
    String redirectUri = "http://localhost/openid_connect_login";
    String scopes = "openid profile";
    String responseTypes = "code";

    Map<String, Object> clientMetadata = new HashMap<>();
    clientMetadata.put("client_id", clientId);
    clientMetadata.put("client_secret", clientSecret);
    clientMetadata.put("redirect_uris", Set.of(redirectUri));
    clientMetadata.put("response_types", Set.of(responseTypes));
    clientMetadata.put("scope", scopes);

    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(iss)
      .subject(sub)
      .issueTime(iat)
      .expirationTime(exp)
      .audience(aud);

    claims.claim("trust_anchor", ta);
    claims.claim("authority_hints", List.of("https://ta1.example.com"));
    claims.claim("metadata", Map.of("openid_relying_party", clientMetadata));

    RSAKey rsaKey = TrustChainTestFactory.keyFor(iss);
    JWSSigner signer = new RSASSASigner(rsaKey);
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build();
    SignedJWT signedJWT = new SignedJWT(header, claims.build());
    signedJWT.sign(signer);
    return signedJWT.serialize();
  }

  private void performCall(String iss, String sub, Date iat, Date exp, String aud, String ta)
      throws Exception {

    String rpJwt = opJwtResponse(iss, sub, iat, exp, aud, ta);

    mockRtf.getMockServer()
      .expect(requestTo("https://op.example.com/fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess(rpJwt, MediaType.APPLICATION_JSON));

    mvc.perform(get("/openid_connect_login?iss=" + iss))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern("/login?error=true"));
  }
}
