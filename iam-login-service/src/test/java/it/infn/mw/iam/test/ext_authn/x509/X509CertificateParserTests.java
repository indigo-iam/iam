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

import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;

import it.infn.mw.iam.authn.x509.CertificateParsingError;
import it.infn.mw.iam.authn.x509.PEMX509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParsingResult;

public class X509CertificateParserTests extends X509TestSupport {


  @Test
  public void testCertificateParsing() {
    X509CertificateChainParser parser = new PEMX509CertificateChainParser();
    X509CertificateChainParsingResult result = parser.parseChainFromString(TEST_0_CERT_STRING);

    assertThat(result.getChain(), arrayWithSize(1));
    assertThat(result.getChain()[0].getSubjectX500Principal().getName(), equalTo(TEST_0_SUBJECT));

  }

  @Test(expected = CertificateParsingError.class)
  public void testCertificateParsingFailsWithGarbage() {
    X509CertificateChainParser parser = new PEMX509CertificateChainParser();
    try {
      parser.parseChainFromString("48327498dsahtdsadasgyr9");
    } catch (RuntimeException e) {
      assertThat(e.getMessage(), containsString("PEM data not found"));
      throw e;
    }
  }

  @Test(expected = CertificateParsingError.class)
  public void testCertificateParsingFailsWithEmptyString() {
    X509CertificateChainParser parser = new PEMX509CertificateChainParser();
    try {
      parser.parseChainFromString("");
    } catch (RuntimeException e) {
      assertThat(e.getMessage(), containsString("PEM data not found"));
      throw e;
    }
  }
}
