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

import static org.hamcrest.Matchers.emptyArray;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.security.cert.X509Certificate;

import org.junit.Test;

import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.X509CertificateVerificationResult;

public class X509AuthenticationCredentialTests {

  public static final String TEST_SUBJECT = "Test subject";
  public static final String TEST_ISSUER = "Test issuer";
  public static final String VERIFICATION_ERROR = "Verification error";

  @Test
  public void testCredentialCreation() {
    IamX509AuthenticationCredential.Builder builder = new IamX509AuthenticationCredential.Builder();
    IamX509AuthenticationCredential cred = builder.subject(TEST_SUBJECT)
      .issuer(TEST_ISSUER)
      .verificationResult(X509CertificateVerificationResult.failed(VERIFICATION_ERROR))
      .certificateChain(new X509Certificate[] {})
      .build();

    assertThat(cred.getSubject(), equalTo(TEST_SUBJECT));
    assertThat(cred.getIssuer(), equalTo(TEST_ISSUER));
    assertThat(cred.getVerificationResult().status(),
        is(X509CertificateVerificationResult.Status.FAILED));

    assertThat(cred.getVerificationResult().error().get(),
        equalTo(VERIFICATION_ERROR));
    
    assertThat(cred.getCertificateChain(), emptyArray());
  }

}
