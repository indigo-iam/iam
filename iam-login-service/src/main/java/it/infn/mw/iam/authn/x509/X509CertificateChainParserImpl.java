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
package it.infn.mw.iam.authn.x509;

import static eu.emi.security.authn.x509.impl.CertificateUtils.configureSecProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.springframework.stereotype.Component;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

@Component
public class X509CertificateChainParserImpl implements X509CertificateChainParser {

  public X509CertificateChainParserImpl() {
    configureSecProvider();
  }

  @Override
  public X509CertificateChainParsingResult parseChainFromString(String certString) {

    if (isPEMFormat(certString)) {
      return parsePEM(certString);
    } else {
      return parseDER(certString);
    }
  }

  private boolean isPEMFormat(String certString) {
    return certString.contains("-----BEGIN CERTIFICATE-----");
  }


  private X509CertificateChainParsingResult parsePEM(String certString) {
    String pemString;

    if (certString.contains("\t")) {
      pemString = certString.replace("\t", "\n");
    } else if (certString.contains("%0A")) {
      pemString = URLDecoder.decode(certString, StandardCharsets.UTF_8);
    } else {
      pemString = certString;
    }

    InputStream stream = new ByteArrayInputStream(pemString.getBytes(StandardCharsets.US_ASCII));
    try {
      X509Certificate[] chain = CertificateUtils.loadCertificateChain(stream, Encoding.PEM);
      return X509CertificateChainParsingResult.from(pemString, chain);

    } catch (IOException e) {
      final String errorMessage =
          String.format("Error parsing certificate chain: %s", e.getMessage());

      throw new CertificateParsingError(errorMessage, e);
    }
  }

  private X509CertificateChainParsingResult parseDER(String derString) {
    byte[] derBytes = Base64.getDecoder().decode(derString);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(derBytes);

    try {
      X509Certificate[] chain = CertificateUtils.loadCertificateChain(inputStream, Encoding.DER);

      ByteArrayOutputStream pemOutputStream = new ByteArrayOutputStream();
      CertificateUtils.saveCertificateChain(pemOutputStream, chain, Encoding.PEM);
      String pemString = pemOutputStream.toString(StandardCharsets.US_ASCII);

      return X509CertificateChainParsingResult.from(pemString, chain);
    } catch (IOException e) {
      final String errorMessage =
          String.format("Error parsing certificate chain in : %s", e.getMessage());

      throw new CertificateParsingError(errorMessage, e);
    }
  }

}
