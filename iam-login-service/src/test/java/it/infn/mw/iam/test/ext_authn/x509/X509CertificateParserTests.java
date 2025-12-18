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
package it.infn.mw.iam.test.ext_authn.x509;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import it.infn.mw.iam.authn.x509.CertificateParsingError;
import it.infn.mw.iam.authn.x509.X509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParserImpl;
import it.infn.mw.iam.authn.x509.X509CertificateChainParsingResult;

class X509CertificateParserTests extends X509TestSupport {

  @Test
  void testCertificateParsing() {
    X509CertificateChainParser parser = new X509CertificateChainParserImpl();
    X509CertificateChainParsingResult result = parser.parseChainFromString(TEST_0_CERT_STRING);

    assertThat(result.getChain(), arrayWithSize(1));
    assertThat(result.getChain()[0].getSubjectX500Principal().getName(), equalTo(TEST_0_SUBJECT));
  }

  @Test
  void testCertificateParsingFailsWithGarbage() {
    X509CertificateChainParser parser = new X509CertificateChainParserImpl();
    CertificateParsingError e = assertThrows(CertificateParsingError.class,
        () -> parser.parseChainFromString("48327498dsahtdsadasgyr9"));
    assertThat(e.getMessage(), containsString(
        "Error parsing certificate chain: Can not parse the input data as a certificate"));
  }

  @Test
  void testCertificateParsingFailsWithGarbagePEM() {
    String garbagePemString =
        "-----BEGIN CERTIFICATE-----\ngYSByZWFsIGNlcnRpZmljYXRlCg==\n-----END CERTIFICATE-----";
    X509CertificateChainParser parser = new X509CertificateChainParserImpl();
    CertificateParsingError e = assertThrows(CertificateParsingError.class,
        () -> parser.parseChainFromString(garbagePemString));
    assertThat(e.getMessage(), containsString("unable to decode base64 string"));
  }

  @Test
  void testCertificateParsingFailsWithEmptyString() {
    X509CertificateChainParser parser = new X509CertificateChainParserImpl();
    CertificateParsingError e =
        assertThrows(CertificateParsingError.class, () -> parser.parseChainFromString(""));
    assertThat(e.getMessage(), containsString("No valid certificates found"));
  }
}
