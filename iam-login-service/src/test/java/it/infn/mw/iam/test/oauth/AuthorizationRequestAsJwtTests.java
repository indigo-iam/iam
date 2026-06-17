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
package it.infn.mw.iam.test.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.ClientService;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class AuthorizationRequestAsJwtTests {

  @Autowired
  ClientService clientService;

  @Autowired
  MockMvc mvc;

  @Autowired
  Clock clock;

  private KeyPair rsaKeyPair;

  private static final String CLIENT_ID = "request-object-client";
  private static final String REDIRECT_URI = "https://client.example.org/callback";

  @BeforeEach
  void setupTestClient() throws Exception {

    rsaKeyPair = generateRsaKeyPair();

    JWKSet clientJwkSet = buildJwkSet(rsaKeyPair);

    ClientDetailsEntity client = prepareClient(CLIENT_ID);
    client.setRequestObjectSigningAlg(JWSAlgorithm.RS256);
    client.setJwks(clientJwkSet);
    clientService.saveNewClient(client);
  }

  private ClientDetailsEntity prepareClient(String clientId) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId(clientId);
    client.setClientSecret("secret");
    client.setTokenEndpointAuthMethod(AuthMethod.SECRET_POST);
    client.setScope(Set.of("openid", "profile", "email"));
    client.setRedirectUris(Set.of(REDIRECT_URI));
    client.setGrantTypes(Set.of(GrantType.AUTHORIZATION_CODE.getValue()));
    return client;
  }

  private static JWKSet buildJwkSet(KeyPair keyPair) {
    RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
      .privateKey((RSAPrivateKey) keyPair.getPrivate())
      .keyID("rsa1")
      .build();

    return new JWKSet(rsaKey);
  }

  @Test
  void signedRequestObjectIsAccepted() throws Exception {

    String requestObject = signedRequestObject(rsaKeyPair, clock.instant(), CLIENT_ID, "code",
        "openid profile", REDIRECT_URI, "signed-nonce");

    mvc
      .perform(get("/authorize").param("client_id", CLIENT_ID)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", REDIRECT_URI)
        .param("request", requestObject))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"));
  }

  @Test
  void plainRequestObjectIsAcceptedOnlyForClientRegisteredWithAlgNone() throws Exception {

    final String clientId = "plain-request-object-client";
    ClientDetailsEntity client = prepareClient(clientId);
    clientService.saveNewClient(client);

    String requestObject = plainRequestObject(clock.instant(), clientId, "code", "openid profile",
        REDIRECT_URI, "plain-nonce");

    mvc
      .perform(get("/authorize").param("client_id", clientId)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", REDIRECT_URI)
        .param("request", requestObject))
      .andExpect(status().is3xxRedirection());
  }

  @SuppressWarnings("deprecation")
  @Test
  void encryptedRequestObjectIsAccepted() throws Exception {

    String requestObject = encryptedRequestObject(rsaKeyPair, clock.instant(), CLIENT_ID, "code",
        "openid profile", REDIRECT_URI, "encrypted-nonce");

    InvalidRequestException error = (InvalidRequestException) mvc
      .perform(get("/authorize").param("client_id", CLIENT_ID)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", REDIRECT_URI)
        .param("request", requestObject))
      .andExpect(status().isBadRequest())
      .andExpect(view().name("forward:/oauth/error"))
      .andExpect(model().attributeExists("error"))
      .andReturn()
      .getModelAndView()
      .getModel()
      .get("error");

    assertEquals("invalid_request", error.getOAuth2ErrorCode());
    assertTrue(error.getMessage().contains("Invalid Request Object JWT"));
  }

  @Test
  void signedRequestObjectWithWrongSignatureIsRejected() throws Exception {
    KeyPair signingKey = generateRsaKeyPair();

    String requestObject = signedRequestObject(signingKey, clock.instant(), CLIENT_ID, "code",
        "openid profile", REDIRECT_URI, "bad-signature-nonce");

    mvc
      .perform(get("/authorize").param("client_id", CLIENT_ID)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", REDIRECT_URI)
        .param("request", requestObject))
      .andExpect(status().is4xxClientError());
  }

  @Test
  void requestObjectClaimsOverrideQueryParameters() throws Exception {

    String requestObject = signedRequestObject(rsaKeyPair, clock.instant(), CLIENT_ID, "code",
        "openid profile email", REDIRECT_URI, "jwt-nonce");

    mvc
      .perform(get("/authorize").param("client_id", CLIENT_ID)
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", REDIRECT_URI)
        .param("request", requestObject))
      .andExpect(status().is3xxRedirection());
  }

  private static String signedRequestObject(KeyPair keyPair, Instant now, String clientId,
      String responseType, String scope, String redirectUri, String nonce) throws Exception {

    JWTClaimsSet claims = baseClaims(now, clientId, responseType, scope, redirectUri, nonce);

    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), claims);

    jwt.sign(new RSASSASigner(keyPair.getPrivate()));

    return jwt.serialize();
  }

  private static String plainRequestObject(Instant now, String clientId, String responseType,
      String scope, String redirectUri, String nonce) {

    return new PlainJWT(baseClaims(now, clientId, responseType, scope, redirectUri, nonce))
      .serialize();
  }

  private static String encryptedRequestObject(KeyPair recipientKeyPair, Instant now,
      String clientId, String responseType, String scope, String redirectUri, String nonce)
      throws Exception {

    JWTClaimsSet claims = baseClaims(now, clientId, responseType, scope, redirectUri, nonce);

    EncryptedJWT jwt =
        new EncryptedJWT(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
          .contentType("JWT")
          .build(), claims);

    jwt.encrypt(new RSAEncrypter((RSAPublicKey) recipientKeyPair.getPublic()));

    return jwt.serialize();
  }

  private static JWTClaimsSet baseClaims(Instant now, String clientId, String responseType,
      String scope, String redirectUri, String nonce) {

    return new JWTClaimsSet.Builder().issuer(clientId)
      .audience("https://iam.example.org/")
      .claim("client_id", clientId)
      .claim("grant_type", "authorization_code")
      .claim("response_type", responseType)
      .claim("scope", scope)
      .claim("redirect_uri", redirectUri)
      .claim("nonce", nonce)
      .issueTime(Date.from(now))
      .expirationTime(Date.from(now.plusSeconds(300)))
      .build();
  }

  private static KeyPair generateRsaKeyPair() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    return gen.generateKeyPair();
  }
}
