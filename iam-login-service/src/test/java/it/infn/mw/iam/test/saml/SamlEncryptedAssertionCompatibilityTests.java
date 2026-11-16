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
package it.infn.mw.iam.test.saml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.stream.Stream;

import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;

/**
 * Regression coverage for SAML 2 assertion decryption with the legacy OpenSAML 2 stack.
 * No Spring context or external IdP is required.
 */
class SamlEncryptedAssertionCompatibilityTests {

  private static final String AES_256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

  @BeforeAll
  static void bootstrap() throws Exception {
    DefaultBootstrap.bootstrap();
  }

  static Stream<Arguments> algorithmsAndPlacements() {
    return Stream.of(
        Arguments.of(AES_256_GCM, Encrypter.KeyPlacement.INLINE),
        Arguments.of(AES_256_GCM, Encrypter.KeyPlacement.PEER),
        Arguments.of(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
            Encrypter.KeyPlacement.INLINE),
        Arguments.of(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
            Encrypter.KeyPlacement.PEER));
  }

  @ParameterizedTest(name = "{0}, encrypted key placement {1}")
  @MethodSource("algorithmsAndPlacements")
  void encryptsAndDecryptsAssertion(String dataAlgorithm, Encrypter.KeyPlacement placement)
      throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();

    BasicCredential encryptionCredential = new BasicCredential();
    encryptionCredential.setPublicKey(keyPair.getPublic());

    BasicCredential decryptionCredential = new BasicCredential();
    decryptionCredential.setPrivateKey(keyPair.getPrivate());

    Assertion assertion = (Assertion) Configuration.getBuilderFactory()
        .getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(Assertion.DEFAULT_ELEMENT_NAME);
    assertion.setID("_saml-encryption-regression");
    assertion.setIssueInstant(new DateTime());
    assertion.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);

    EncryptionParameters dataParameters = new EncryptionParameters();
    dataParameters.setAlgorithm(dataAlgorithm);

    KeyEncryptionParameters keyParameters = new KeyEncryptionParameters();
    keyParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
    keyParameters.setEncryptionCredential(encryptionCredential);

    Encrypter encrypter = new Encrypter(dataParameters, keyParameters);
    encrypter.setKeyPlacement(placement);
    EncryptedAssertion encrypted = encrypter.encrypt(assertion);

    assertNotNull(encrypted.getEncryptedData());
    assertEquals(dataAlgorithm, encrypted.getEncryptedData().getEncryptionMethod().getAlgorithm());

    Decrypter decrypter = new Decrypter(null,
        new StaticKeyInfoCredentialResolver(decryptionCredential),
        placement == Encrypter.KeyPlacement.INLINE
            ? new InlineEncryptedKeyResolver()
            : new EncryptedElementTypeEncryptedKeyResolver());
    decrypter.setRootInNewDocument(true);

    Assertion decrypted = decrypter.decrypt(encrypted);
    assertNotNull(decrypted);
    assertEquals(assertion.getID(), decrypted.getID());
    assertEquals(assertion.getVersion(), decrypted.getVersion());
  }
}
