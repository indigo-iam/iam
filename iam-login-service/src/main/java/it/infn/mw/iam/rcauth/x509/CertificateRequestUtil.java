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
package it.infn.mw.iam.rcauth.x509;

import static eu.emi.security.authn.x509.helpers.CertificateHelpers.toX500Name;
import static eu.emi.security.authn.x509.impl.X500NameUtils.getX500Principal;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemWriter;

import eu.emi.security.authn.x509.helpers.proxy.ProxyGeneratorHelper;

public class CertificateRequestUtil {
  
  public static final String BEGIN_CERT_REQ = "-----BEGIN CERTIFICATE REQUEST-----";
  public static final String END_CERT_REQ = "-----END CERTIFICATE REQUEST-----";

  private CertificateRequestUtil() {
    // prevent instantiation
  }

  public static CertificateRequestHolder buildCertificateRequest(String subject, int keySize)
      throws IOException, OperatorCreationException {

    KeyPair kp = ProxyGeneratorHelper.generateKeyPair(keySize);
    PKCS10CertificationRequestBuilder builder;

    try (ASN1InputStream is = new ASN1InputStream(kp.getPublic().getEncoded())) {

      SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(is.readObject());

      X500Name dn = toX500Name(getX500Principal(subject));
      builder = new PKCS10CertificationRequestBuilder(dn, subjectPublicKeyInfo);
      AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(OIWObjectIdentifiers.sha1WithRSA);
      AlgorithmIdentifier hashAi = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
      BcRSAContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(signatureAi, hashAi);
      AsymmetricKeyParameter pkParam = PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());
      ContentSigner signer = csBuilder.build(pkParam);

      PKCS10CertificationRequest request = builder.build(signer);

      return CertificateRequestHolder.build(kp, request);

    }
  }

  public static String certRequestToPemString(PKCS10CertificationRequest request)
      throws IOException {

    StringWriter sw = new StringWriter(); 
    
    try (PemWriter writer = new PemWriter(sw)) {
      writer.writeObject(new MiscPEMGenerator(request)); 
    }
    
    return sw.toString();
  }

  public static String certRequestToBase64String(PKCS10CertificationRequest request) throws IOException {
    String pemString = certRequestToPemString(request);
    pemString = pemString.replace(BEGIN_CERT_REQ, "");
    pemString = pemString.replace(END_CERT_REQ, "");
    return pemString;
  }
}
