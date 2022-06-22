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
import static org.hamcrest.Matchers.is;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.PEMX509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateVerificationResult.Status;

@RunWith(MockitoJUnitRunner.class)
public class X509CredentialExtractorTests extends X509TestSupport {


  @Mock
  HttpServletRequest request;

  DefaultX509AuthenticationCredentialExtractor extractor =
      new DefaultX509AuthenticationCredentialExtractor(new PEMX509CertificateChainParser());

  @Test
  public void testEmptyHeaders() {

    Optional<IamX509AuthenticationCredential> cred = extractor.extractX509Credential(request);
    assertThat(cred.isPresent(), is(false));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testPartialHeadersResultInExceptionThrown() {

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader()))
      .thenReturn(TEST_0_CERT_STRING);

    try {
      extractor.extractX509Credential(request);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), containsString("Required header not found"));
      throw e;
    }
  }

  @Test
  public void testSuccesfullx509Extraction() {
    mockHttpRequestWithTest0SSLHeaders(request);

    IamX509AuthenticationCredential cred = extractor.extractX509Credential(request)
      .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));

    assertThat(cred.getSubject(), equalTo(TEST_0_SUBJECT));
    assertThat(cred.getIssuer(), equalTo(TEST_0_ISSUER));
    assertThat(cred.getCertificateChain(), arrayWithSize(1));
    assertThat(cred.getVerificationResult().status(), is(Status.SUCCESS));
  }
  
  @Test(expected=IllegalArgumentException.class)
  public void testInvalidVerifyHeaderParsing(){
    mockHttpRequestWithTest0SSLHeaders(request);
    mockVerifyHeader(request, "invalid");
    
    try {
      extractor.extractX509Credential(request);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), containsString("Could not parse X.509 certificate verification header"));
      throw e;
    }
  }
  
  @Test
  public void testVerifyHeaderFailureParsing(){
    mockHttpRequestWithTest0SSLHeaders(request);
    mockVerifyHeader(request, "FAILED:invalid whatever");
    
    IamX509AuthenticationCredential cred = extractor.extractX509Credential(request)
        .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));
    
    assertThat(cred.getSubject(), equalTo(TEST_0_SUBJECT));
    assertThat(cred.getIssuer(), equalTo(TEST_0_ISSUER));
    assertThat(cred.getCertificateChain(), arrayWithSize(1));
    
    assertThat(cred.getVerificationResult().status(), is(Status.FAILED));
    assertThat(cred.getVerificationResult().error().get(), equalTo("invalid whatever"));
  }
}
