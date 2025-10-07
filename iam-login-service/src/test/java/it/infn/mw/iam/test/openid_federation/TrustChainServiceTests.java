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

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.core.oidc.InvalidTrustChainException;
import it.infn.mw.iam.core.oidc.TrustAnchorRepository;
import it.infn.mw.iam.core.oidc.TrustChainResolver;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.core.oidc.TrustChainValidator;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@RunWith(MockitoJUnitRunner.class)
public class TrustChainServiceTests {

  @Mock
  TrustAnchorRepository trustAnchorRepository;

  @Mock
  RestTemplate restTemplate;

  @Mock
  TrustChainValidator validator;

  @Mock
  TrustChainResolver resolver;

  @InjectMocks
  TrustChainService service;

  TrustChain fakeChain;

  @Before
  public void setup() {
    TrustChainResolver realResolver = new TrustChainResolver();
    TrustChainValidator realValidator = new TrustChainValidator(trustAnchorRepository);
    ReflectionTestUtils.setField(realResolver, "restTemplate", restTemplate);
    ReflectionTestUtils.setField(service, "validator", realValidator);
    ReflectionTestUtils.setField(service, "resolver", realResolver);
  }

  private void mockRpToTaChain(boolean taTrusted) throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(null);
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    EntityStatement taES = fakeChain.getSuperiorStatements().get(0);
    String taEsJwt = taES.getSignedStatement().serialize();

    // Build TA EC (self-issued)
    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    String taEcJwt = taEC.getSignedStatement().serialize();

    when(
        restTemplate.getForObject("https://rp.example/.well-known/openid-federation", String.class))
          .thenReturn(rpJwt);

    when(restTemplate.getForObject("https://ta.example/fetch?sub=https%3A%2F%2Frp.example",
        String.class)).thenReturn(taEsJwt);

    when(
        restTemplate.getForObject("https://ta.example/.well-known/openid-federation", String.class))
          .thenReturn(taEcJwt);

    // TA trusted?
    when(trustAnchorRepository.isTrusted("https://ta.example")).thenReturn(taTrusted);
  }

  @Test
  public void testResolveTrustChainFromRpToTa() throws Exception {
    mockRpToTaChain(true);

    TrustChain result = service.validateFromEntityId("https://rp.example");

    assertEquals("https://ta.example", result.getTrustAnchorEntityID().getValue());
  }

  @Test(expected = InvalidTrustChainException.class)
  public void testUntrustedTrustAnchor() throws Exception {
    mockRpToTaChain(false);

    service.validateFromEntityId("https://rp.example");
  }

  @Test
  public void testResolveTrustChainFromRpToIntermediateToTa() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToIntermediateToTaChain("https://ta.example");

    // RP EC (leaf)
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    // Intermediate EC (self-signed)
    EntityStatement iaEC = TrustChainTestFactory.selfEC("https://intermediate.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), List.of(new EntityID("https://ta.example")),
        "https://intermediate.example/fetch", null, null);
    String iaEcJwt = iaEC.getSignedStatement().serialize();

    // Intermediate ES → RP
    EntityStatement intermToRp = fakeChain.getSuperiorStatements().get(0);
    String intermToRpJwt = intermToRp.getSignedStatement().serialize();

    // TA ES → Intermediate
    EntityStatement taToInterm = fakeChain.getSuperiorStatements().get(1);
    String taToIntermJwt = taToInterm.getSignedStatement().serialize();

    // TA EC (self-signed)
    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    String taEcJwt = taEC.getSignedStatement().serialize();

    when(
        restTemplate.getForObject("https://rp.example/.well-known/openid-federation", String.class))
          .thenReturn(rpJwt);

    when(restTemplate.getForObject("https://intermediate.example/.well-known/openid-federation",
        String.class)).thenReturn(iaEcJwt);

    when(restTemplate.getForObject(
        "https://intermediate.example/fetch?sub=https%3A%2F%2Frp.example", String.class))
          .thenReturn(intermToRpJwt);

    when(restTemplate.getForObject(
        "https://ta.example/fetch?sub=https%3A%2F%2Fintermediate.example", String.class))
          .thenReturn(taToIntermJwt);

    when(
        restTemplate.getForObject("https://ta.example/.well-known/openid-federation", String.class))
          .thenReturn(taEcJwt);

    when(trustAnchorRepository.isTrusted("https://ta.example")).thenReturn(true);

    TrustChain resolved = service.validateFromEntityId("https://rp.example");

    assertEquals("https://ta.example", resolved.getTrustAnchorEntityID().getValue());
    // Superior Statements include also the TA EC
    assertEquals(3, resolved.getSuperiorStatements().size());
  }

  @Test
  public void testValidatorReturnsTheShortestChainBetweenTheTwoValidOnes()
      throws JOSEException, BadJOSEException {
    OIDCClientMetadata rpMetadata = new OIDCClientMetadata();
    rpMetadata.setClientRegistrationTypes(List.of(ClientRegistrationType.EXPLICIT));

    // Entity Configuration of RP
    EntityStatement rpEC =
        TrustChainTestFactory.selfEC("https://rp.example", new Date(),
            new Date(System.currentTimeMillis() + 600000), List
              .of(new EntityID("https://ta.example"), new EntityID("https://intermediate.example")),
            null, rpMetadata, null);
    String rpEcJwt = rpEC.getSignedStatement().serialize();

    // Entity Configuration of IA
    EntityStatement iaEC = TrustChainTestFactory.selfEC("https://intermediate.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), List.of(new EntityID("https://ta.example")),
        "https://intermediate.example/fetch", null, null);
    String iaEcJwt = iaEC.getSignedStatement().serialize();

    // Entity Configuration of TA
    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    String taEcJwt = taEC.getSignedStatement().serialize();

    TrustChain shorterChain = TrustChainTestFactory.createRpToTaChain(null);
    TrustChain longerChain =
        TrustChainTestFactory.createRpToIntermediateToTaChain("https://ta.example");

    // Intermediate ES → RP
    EntityStatement intermToRp = longerChain.getSuperiorStatements().get(0);
    String intermToRpJwt = intermToRp.getSignedStatement().serialize();

    // TA ES → Intermediate
    EntityStatement taToInterm = longerChain.getSuperiorStatements().get(1);
    String taToIntermJwt = taToInterm.getSignedStatement().serialize();

    // TA ES → RP
    EntityStatement taToRp = shorterChain.getSuperiorStatements().get(0);
    String taToRpJwt = taToRp.getSignedStatement().serialize();

    when(
        restTemplate.getForObject("https://rp.example/.well-known/openid-federation", String.class))
          .thenReturn(rpEcJwt);

    when(restTemplate.getForObject("https://intermediate.example/.well-known/openid-federation",
        String.class)).thenReturn(iaEcJwt);

    when(restTemplate.getForObject(
        "https://intermediate.example/fetch?sub=https%3A%2F%2Frp.example", String.class))
          .thenReturn(intermToRpJwt);

    when(restTemplate.getForObject(
        "https://ta.example/fetch?sub=https%3A%2F%2Fintermediate.example", String.class))
          .thenReturn(taToIntermJwt);

    when(restTemplate.getForObject("https://ta.example/fetch?sub=https%3A%2F%2Frp.example",
        String.class)).thenReturn(taToRpJwt);

    when(
        restTemplate.getForObject("https://ta.example/.well-known/openid-federation", String.class))
          .thenReturn(taEcJwt);

    when(trustAnchorRepository.isTrusted("https://ta.example")).thenReturn(true);

    TrustChain resolved = service.validateFromEntityId("https://rp.example");

    assertEquals("https://ta.example", resolved.getTrustAnchorEntityID().getValue());
    assertEquals(2, resolved.getSuperiorStatements().size());
  }

  @Test
  public void testValidatorReturnsValidChain() throws JOSEException, BadJOSEException {
    OIDCClientMetadata rpMetadata = new OIDCClientMetadata();
    rpMetadata.setClientRegistrationTypes(List.of(ClientRegistrationType.EXPLICIT));

    // Entity Configuration of RP
    EntityStatement rpEC =
        TrustChainTestFactory.selfEC("https://rp.example", new Date(),
            new Date(System.currentTimeMillis() + 600000), List
              .of(new EntityID("https://ta.example"), new EntityID("https://intermediate.example")),
            null, rpMetadata, null);
    String rpEcJwt = rpEC.getSignedStatement().serialize();

    // Entity Configuration of IA
    EntityStatement iaEC = TrustChainTestFactory.selfEC("https://intermediate.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), List.of(new EntityID("https://ta1.example")),
        "https://intermediate.example/fetch", null, null);
    String iaEcJwt = iaEC.getSignedStatement().serialize();

    // Entity Configuration of trusted TA
    EntityStatement trustedTaEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    String trustedTaEcJwt = trustedTaEC.getSignedStatement().serialize();

    // Entity Configuration of untrusted TA
    EntityStatement untrustedTaEC = TrustChainTestFactory.selfEC("https://ta1.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta1.example/fetch", null,
        null);
    String untrustedTaEcJwt = untrustedTaEC.getSignedStatement().serialize();

    TrustChain shorterChain = TrustChainTestFactory.createRpToTaChain(null);
    TrustChain longerChain =
        TrustChainTestFactory.createRpToIntermediateToTaChain("https://ta1.example");

    // Intermediate ES → RP
    EntityStatement intermToRp = longerChain.getSuperiorStatements().get(0);
    String intermToRpJwt = intermToRp.getSignedStatement().serialize();

    // Untrusted TA ES → Intermediate
    EntityStatement taToInterm = longerChain.getSuperiorStatements().get(1);
    String taToIntermJwt = taToInterm.getSignedStatement().serialize();

    // Trusted TA ES → RP
    EntityStatement taToRp = shorterChain.getSuperiorStatements().get(0);
    String taToRpJwt = taToRp.getSignedStatement().serialize();

    when(
        restTemplate.getForObject("https://rp.example/.well-known/openid-federation", String.class))
          .thenReturn(rpEcJwt);

    when(restTemplate.getForObject("https://intermediate.example/.well-known/openid-federation",
        String.class)).thenReturn(iaEcJwt);

    when(restTemplate.getForObject(
        "https://intermediate.example/fetch?sub=https%3A%2F%2Frp.example", String.class))
          .thenReturn(intermToRpJwt);

    when(restTemplate.getForObject(
        "https://ta1.example/fetch?sub=https%3A%2F%2Fintermediate.example", String.class))
          .thenReturn(taToIntermJwt);

    when(restTemplate.getForObject("https://ta.example/fetch?sub=https%3A%2F%2Frp.example",
        String.class)).thenReturn(taToRpJwt);

    when(
        restTemplate.getForObject("https://ta.example/.well-known/openid-federation", String.class))
          .thenReturn(trustedTaEcJwt);

    when(restTemplate.getForObject("https://ta1.example/.well-known/openid-federation",
        String.class)).thenReturn(untrustedTaEcJwt);

    when(trustAnchorRepository.isTrusted("https://ta.example")).thenReturn(true);
    when(trustAnchorRepository.isTrusted("https://ta1.example")).thenReturn(false);

    TrustChain resolved = service.validateFromEntityId("https://rp.example");

    assertEquals("https://ta.example", resolved.getTrustAnchorEntityID().getValue());
    assertEquals(2, resolved.getSuperiorStatements().size());
  }

  @Test
  public void testValidateClaimsThrowsWhenIatInFuture() throws JOSEException {
    Date futureIat = new Date(System.currentTimeMillis() + 60000);
    Date exp = new Date(System.currentTimeMillis() + 600000);

    EntityStatement es = TrustChainTestFactory.selfEC("https://rp.example", futureIat, exp, null,
        "https://rp.example/fetch", null, null);

    InvalidTrustChainException ex = assertThrows(InvalidTrustChainException.class,
        () -> ReflectionTestUtils.invokeMethod(validator, "validateClaims", es));
    assertEquals("invalid_trust_chain", ex.getErrorCode());
    assertTrue(ex.getMessage().contains("Entity Statement has iat in the future"));
  }

  @Test
  public void testValidateClaimsThrowsWhenExpired() throws JOSEException {
    Date iat = new Date(System.currentTimeMillis() - 600000);
    Date exp = new Date(System.currentTimeMillis() - 60000);

    EntityStatement es = TrustChainTestFactory.selfEC("https://rp.example", iat, exp, null,
        "https://rp.example/fetch", null, null);

    InvalidTrustChainException ex = assertThrows(InvalidTrustChainException.class,
        () -> ReflectionTestUtils.invokeMethod(validator, "validateClaims", es));
    assertEquals("invalid_trust_chain", ex.getErrorCode());
    assertTrue(ex.getMessage().contains("Entity Statement is expired"));
  }

  @Test
  public void testValidateFromEntityConfiguration() throws Exception {
    mockRpToTaChain(true);
    EntityStatement ec = fakeChain.getLeafSelfStatement();

    TrustChain result = service.validateFromEntityConfiguration(ec);

    assertEquals("https://ta.example", result.getTrustAnchorEntityID().getValue());
  }

  @Test
  public void testValidateFromProvidedChain() throws Exception {
    mockRpToTaChain(true);
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    List<EntityStatement> superiors = fakeChain.getSuperiorStatements();
    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    List<EntityStatement> chain = new ArrayList<>();
    chain.add(rpEC);
    chain.addAll(superiors);
    chain.add(taEC);

    TrustChain result = service.validateFromProvidedChain(chain);

    assertEquals("https://ta.example", result.getTrustAnchorEntityID().getValue());
  }

  @Test
  public void testFetchEntityConfigurationFailure() {
    String entityId = "https://rp.example";

    InvalidTrustChainException ex = assertThrows(InvalidTrustChainException.class,
        () -> ReflectionTestUtils.invokeMethod(resolver, "fetchEntityConfiguration", entityId));

    assertEquals("invalid_trust_chain", ex.getErrorCode());
    assertTrue(ex.getMessage().contains("Failed to fetch EC"));
  }

  @Test
  public void testFetchEntityStatementFailure() {
    String fetchEndpoint = "https://ta.example/fetch";
    String subject = "https://rp.example";
    String issuer = "https://ta.example";

    InvalidTrustChainException ex =
        assertThrows(InvalidTrustChainException.class, () -> ReflectionTestUtils
          .invokeMethod(resolver, "fetchEntityStatement", fetchEndpoint, issuer, subject));

    assertEquals("invalid_trust_chain", ex.getErrorCode());
    assertTrue(ex.getMessage().contains("Failed to fetch entity statement"));
  }

  @Test(expected = InvalidTrustChainException.class)
  public void testMissingFetchEndpoint() throws JOSEException {
    fakeChain = TrustChainTestFactory.createRpToTaChain(null);
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, null, null, null);
    String taEcJwt = taEC.getSignedStatement().serialize();

    when(
        restTemplate.getForObject("https://rp.example/.well-known/openid-federation", String.class))
          .thenReturn(rpJwt);

    when(
        restTemplate.getForObject("https://ta.example/.well-known/openid-federation", String.class))
          .thenReturn(taEcJwt);

    service.validateFromEntityId("https://rp.example");
  }
}
