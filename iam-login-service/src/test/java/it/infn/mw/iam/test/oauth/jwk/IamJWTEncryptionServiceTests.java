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
package it.infn.mw.iam.test.oauth.jwk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.jwk.IamJWTEncryptionService;
import it.infn.mw.iam.core.jwk.JwkKeyStore;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
public class IamJWTEncryptionServiceTests {

  private static final String KEY_ID = "test-rsa";
  private KeyPair rsaKeyPair;

  private IamJWTEncryptionService serviceWithRsaKey() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    rsaKeyPair = generator.generateKeyPair();

    RSAKey rsaJwk = new RSAKey.Builder((RSAPublicKey) rsaKeyPair.getPublic())
      .privateKey((RSAPrivateKey) rsaKeyPair.getPrivate())
      .keyID(KEY_ID)
      .build();

    JwkKeyStore keyStore = JwkKeyStore.from(new JWKSet(rsaJwk));
    return new IamJWTEncryptionService(keyStore, Optional.of(KEY_ID));
  }

  private JWEObject jweObject(JWEAlgorithm algorithm) {
    JWEHeader header = new JWEHeader.Builder(algorithm, EncryptionMethod.A256GCM).build();
    return new JWEObject(header, new Payload("test payload"));
  }

  private String createNimbusRsa15Jwe() throws Exception {
    JWEObject jwt = jweObject(JWEAlgorithm.RSA1_5);
    jwt.encrypt(new RSAEncrypter((RSAPublicKey) rsaKeyPair.getPublic()));
    return jwt.serialize();
  }

  @Test
  void supportedAlgorithmsExcludeRsa15ButKeepOaep() throws Exception {
    IamJWTEncryptionService service = serviceWithRsaKey();

    assertFalse(service.getAllEncryptionAlgsSupported().contains(JWEAlgorithm.RSA1_5));
    assertTrue(service.getAllEncryptionAlgsSupported().contains(JWEAlgorithm.RSA_OAEP_256));
  }

  @Test
  void encryptRejectsRsa15() throws Exception {
    IamJWTEncryptionService service = serviceWithRsaKey();
    JWEObject jwt = jweObject(JWEAlgorithm.RSA1_5);

    assertThrows(IllegalArgumentException.class, () -> service.encryptJwt(jwt));
  }

  @Test
  void decryptRejectsRsa15() throws Exception {
    IamJWTEncryptionService service = serviceWithRsaKey();
    String compactJwe = createNimbusRsa15Jwe();
    JWEObject incoming = JWEObject.parse(compactJwe);

    assertThrows(IllegalArgumentException.class, () -> service.decryptJwt(incoming));
  }

  @Test
  void encryptAndDecryptStillWorkWithRsaOaep256() throws Exception {
    IamJWTEncryptionService service = serviceWithRsaKey();
    JWEObject jwt = jweObject(JWEAlgorithm.RSA_OAEP_256);

    service.encryptJwt(jwt);
    assertEquals(JWEObject.State.ENCRYPTED, jwt.getState());

    service.decryptJwt(jwt);
    assertEquals(JWEObject.State.DECRYPTED, jwt.getState());
  }
}
