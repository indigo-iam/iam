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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

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

import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AutomaticClientRegistrationTests {

  @Value("${iam.issuer}")
  private String issuer;

  @Autowired
  private MockMvc mvc;

  @MockBean
  private TrustChainService trustChainService;

  @MockBean
  private JWKSetCacheService jwkService;

  private TrustChain fakeChain;

  private RSAKey rsaJWK;

  @Before
  public void setup() throws Exception {
    rsaJWK = new RSAKeyGenerator(2048).keyID("rsa1").generate();

    JWKSet jwkSet = new JWKSet(rsaJWK.toPublicJWK());
    JWKSetKeyStore keyStore = new JWKSetKeyStore(jwkSet);
    JWTSigningAndValidationService validator = new DefaultJWTSigningAndValidationService(keyStore);

    when(jwkService.getValidator(anyString())).thenReturn(validator);
  }

  private String generateRequestJWT(String entityId, String redirectUri, List<String> trustChain)
      throws Exception {
    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(entityId)
      .audience(issuer)
      .subject(entityId)
      .issueTime(new Date())
      .expirationTime(Date.from(Instant.now().plusSeconds(300)))
      .claim("client_id", entityId)
      .claim("redirect_uri", redirectUri)
      .claim("trust_chain", trustChain)
      .build();

    SignedJWT signedJWT =
        new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID())
          .type(JOSEObjectType.JWT)
          .build(), claims);

    signedJWT.sign(new RSASSASigner(rsaJWK.toPrivateKey()));

    return signedJWT.serialize();
  }

  @Test
  public void testAutomaticClientRegistrationWithEntityId() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer);

    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";
    String requestJwt = generateRequestJWT(rpEntityId, redirectUri, null);

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

    String location = result.getResponse().getHeader("Location");
    assertEquals("http://localhost/login", location);
  }

  @Test
  public void testAutomaticClientRegistrationWithTrustChain() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer);

    String rpEntityId = "https://rp.example";
    String redirectUri = "https://rp.example/cb";

    EntityStatement taEC = TrustChainTestFactory.selfEC("https://ta.example", new Date(),
        new Date(System.currentTimeMillis() + 600000), null, "https://ta.example/fetch", null,
        null);
    List<EntityStatement> statements = new ArrayList<>();
    statements.add(fakeChain.getLeafSelfStatement());
    statements.addAll(fakeChain.getSuperiorStatements());
    statements.add(taEC);
    List<String> trustChainStrings = statements.stream()
      .map(es -> es.getSignedStatement().serialize())
      .collect(Collectors.toList());

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

    String location = result.getResponse().getHeader("Location");
    assertEquals("http://localhost/login", location);
  }
}
