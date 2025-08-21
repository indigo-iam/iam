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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

import java.net.URI;
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
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.core.oidc.TrustAnchorRepository;
import it.infn.mw.iam.core.oidc.TrustChainService;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@RunWith(MockitoJUnitRunner.class)
public class TrustChainServiceTests {

  @Mock
  TrustAnchorRepository trustAnchorRepository;

  @Mock
  RestTemplate restTemplate;

  @InjectMocks
  TrustChainService service;

  TrustChain fakeChain;

  @Before
  public void setup() throws JOSEException {
    fakeChain = TrustChainTestFactory.createRpToTaChain();
  }

  @Test
  public void testResolveTrustChainFromRpToTa() throws Exception {
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    EntityStatement taES = fakeChain.getSuperiorStatements().get(0);
    String taEsJwt = taES.getSignedStatement().serialize();

    // Build TA EC (self-issued)
    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600_000), null,
        URI.create("https://ta.example/fetch"), null);
    String taEcJwt = taEC.getSignedStatement().serialize();

    // Mock HTTP responses
    when(
        restTemplate.getForObject("https://rp.example/.well-known/openid-federation", String.class))
          .thenReturn(rpJwt);

    when(restTemplate.getForObject("https://ta.example/fetch?sub=https%3A%2F%2Frp.example",
        String.class)).thenReturn(taEsJwt);

    when(
        restTemplate.getForObject("https://ta.example/.well-known/openid-federation", String.class))
          .thenReturn(taEcJwt);

    // Inject mock
    ReflectionTestUtils.setField(service, "restTemplate", restTemplate);

    // TA trusted
    when(trustAnchorRepository.isTrusted("https://ta.example")).thenReturn(true);

    TrustChain resolved = service.resolveTrustChain("https://rp.example");

    assertNotNull(resolved);
    assertEquals("https://ta.example", resolved.getTrustAnchorEntityID().getValue());
  }

  @Test
  public void testResolveTrustChainFromRpToIntermediateToTa() throws Exception {
    TrustChain fakeChain = TrustChainTestFactory.createRpToIntermediateToTaChain();

    // RP EC (leaf)
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    // Intermediate EC (self-signed)
    EntityStatement iaEC = TrustChainTestFactory.selfEC("https://intermediate.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), List.of(new EntityID("https://ta.example")),
        URI.create("https://intermediate.example/fetch"), null);
    String iaEcJwt = iaEC.getSignedStatement().serialize();

    // Intermediate ES → RP
    EntityStatement intermToRp = fakeChain.getSuperiorStatements().get(0);
    String intermToRpJwt = intermToRp.getSignedStatement().serialize();

    // TA ES → Intermediate
    EntityStatement taToInterm = fakeChain.getSuperiorStatements().get(1);
    String taToIntermJwt = taToInterm.getSignedStatement().serialize();

    // TA EC (self-signed)
    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, URI.create("https://ta.example/fetch"),
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

    ReflectionTestUtils.setField(service, "restTemplate", restTemplate);

    when(trustAnchorRepository.isTrusted("https://ta.example")).thenReturn(true);

    TrustChain resolved = service.resolveTrustChain("https://rp.example");

    // Assertions
    assertNotNull(resolved);
    assertEquals("https://ta.example", resolved.getTrustAnchorEntityID().getValue());
    assertEquals(3, resolved.getSuperiorStatements().size());
  }
}
