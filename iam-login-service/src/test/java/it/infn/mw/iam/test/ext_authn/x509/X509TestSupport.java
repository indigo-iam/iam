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

import static it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter.X509_CREDENTIAL_SESSION_KEY;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.PEMCredential;
import it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

public class X509TestSupport {

  public static final String TEST_0_CERT_PATH = "src/test/resources/x509/test0.cert.pem";
  public static final String TEST_0_KEY_PATH = "src/test/resources/x509/test0.key.pem";

  public static final String TEST_0_SUBJECT = "CN=test0,O=IGI,C=IT";
  public static final String TEST_0_ISSUER = "CN=Test CA,O=IGI,C=IT";
  public static final String TEST_0_SERIAL = "09";
  public static final String TEST_0_V_START = "Sep 26 15:39:34 2012 GMT";
  public static final String TEST_0_V_END = "Sep 24 15:39:34 2022 GMT";

  public static final String TEST_1_CERT_PATH = "src/test/resources/x509/test1.cert.pem";
  public static final String TEST_1_SUBJECT = "CN=test1,O=IGI,C=IT";
  public static final String TEST_1_ISSUER = "CN=Test CA,O=IGI,C=IT";
  public static final String TEST_1_SERIAL = "10";
  public static final String TEST_1_V_START = "Sep 26 15:39:36 2012 GMT";
  public static final String TEST_1_V_END = "Sep 24 15:39:36 2022 GMT";

  public static final String RCAUTH_CA_CERT_PATH = "src/test/resources/x509/rcauth-mock-ca.p12";
  public static final String RCAUTH_CA_CERT_PASSWORD = "pass123";

  public static final String RCAUTH_CA_SUBJECT = "CN=RCAuth Mock CA,O=INDIGO-IAM,C=IT";

  protected X509Certificate TEST_0_CERT;
  protected String TEST_0_CERT_STRING;
  protected String TEST_0_CERT_STRING_NGINX;

  protected X509Certificate TEST_1_CERT;
  protected String TEST_1_CERT_STRING;
  protected String TEST_1_CERT_STRING_NGINX;

  protected IamX509Certificate TEST_0_IAM_X509_CERT;
  protected IamX509Certificate TEST_1_IAM_X509_CERT;

  protected PEMCredential TEST_0_PEM_CREDENTIAL;

  protected String TEST_0_CERT_LABEL = "TEST 0 cert label";
  protected String TEST_1_CERT_LABEL = "TEST 1 cert label";

  protected String TEST_USERNAME = "test";
  protected String TEST_PASSWORD = "password";

  protected X509Credential RCAUTH_CA_CRED;

  protected X509TestSupport() {
    try {
      TEST_0_CERT_STRING = new String(Files.readAllBytes(Paths.get(TEST_0_CERT_PATH)));

      TEST_0_CERT = CertificateUtils.loadCertificate(
          new ByteArrayInputStream(TEST_0_CERT_STRING.getBytes(StandardCharsets.US_ASCII)),
          Encoding.PEM);

      TEST_1_CERT_STRING = new String(Files.readAllBytes(Paths.get(TEST_1_CERT_PATH)));

      TEST_1_CERT = CertificateUtils.loadCertificate(
          new ByteArrayInputStream(TEST_1_CERT_STRING.getBytes(StandardCharsets.US_ASCII)),
          Encoding.PEM);

      TEST_0_IAM_X509_CERT = new IamX509Certificate();
      TEST_0_IAM_X509_CERT.setCertificate(TEST_0_CERT_STRING);
      TEST_0_IAM_X509_CERT.setSubjectDn(TEST_0_SUBJECT);
      TEST_0_IAM_X509_CERT.setIssuerDn(TEST_0_ISSUER);
      TEST_0_IAM_X509_CERT.setLabel(TEST_0_CERT_LABEL);
      TEST_0_IAM_X509_CERT.setPrimary(false);

      TEST_1_IAM_X509_CERT = new IamX509Certificate();
      TEST_1_IAM_X509_CERT.setCertificate(TEST_1_CERT_STRING);
      TEST_1_IAM_X509_CERT.setSubjectDn(TEST_1_SUBJECT);
      TEST_1_IAM_X509_CERT.setIssuerDn(TEST_1_ISSUER);
      TEST_1_IAM_X509_CERT.setLabel(TEST_1_CERT_LABEL);
      TEST_1_IAM_X509_CERT.setPrimary(false);

      // This is how NGINX encodes certficate in the header
      TEST_0_CERT_STRING_NGINX = TEST_0_CERT_STRING.replace('\n', '\t');
      TEST_1_CERT_STRING_NGINX = TEST_1_CERT_STRING.replace('\n', '\t');

      TEST_0_PEM_CREDENTIAL =
          new PEMCredential(TEST_0_KEY_PATH, TEST_0_CERT_PATH, "pass".toCharArray());

      RCAUTH_CA_CRED =
          new KeystoreCredential(RCAUTH_CA_CERT_PATH, RCAUTH_CA_CERT_PASSWORD.toCharArray(),
              RCAUTH_CA_CERT_PASSWORD.toCharArray(), null, "PKCS12");

    } catch (IOException | KeyStoreException | CertificateException e) {
      throw new AssertionError(e.getMessage(), e);
    }
  }

  protected void mockVerifyHeader(HttpServletRequest request, String content) {
    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader()))
      .thenReturn(content);

  }

  protected MockHttpSession loginAsTestUserWithTest0Cert(MockMvc mvc) throws Exception {

    MockHttpSession session =
        (MockHttpSession) mvc.perform(get("/").headers(test0SSLHeadersVerificationSuccess()))
          .andExpect(status().isFound())
          .andExpect(redirectedUrl("http://localhost/login"))
          .andExpect(MockMvcResultMatchers.request()
            .sessionAttribute(X509_CREDENTIAL_SESSION_KEY, notNullValue()))
          .andReturn()
          .getRequest()
          .getSession();

    session = (MockHttpSession) mvc
      .perform(post("/login").session(session)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/"))
      .andExpect(authenticated().withUsername("test"))
      .andReturn()
      .getRequest()
      .getSession();

    return session;
  }

  protected void linkTest1CertificateToAccount(IamAccount account) {
    IamX509Certificate test1Cert = new IamX509Certificate();
    test1Cert.setPrimary(false);

    test1Cert.setCertificate(TEST_1_CERT_STRING);
    test1Cert.setSubjectDn(TEST_1_SUBJECT);
    test1Cert.setIssuerDn(TEST_1_ISSUER);

    test1Cert.setLabel(TEST_1_CERT_LABEL);

    Date now = new Date();

    test1Cert.setCreationTime(now);
    test1Cert.setLastUpdateTime(now);

    test1Cert.setAccount(account);
    account.getX509Certificates().add(test1Cert);
  }

  protected void linkTest0CertificateToAccount(IamAccount account) {
    IamX509Certificate test0Cert = new IamX509Certificate();
    test0Cert.setPrimary(true);

    Date now = new Date();

    test0Cert.setCertificate(TEST_0_CERT_STRING);
    test0Cert.setSubjectDn(TEST_0_SUBJECT);
    test0Cert.setIssuerDn(TEST_0_ISSUER);
    test0Cert.setLabel(TEST_0_CERT_LABEL);

    test0Cert.setCreationTime(now);
    test0Cert.setLastUpdateTime(now);

    test0Cert.setAccount(account);
    account.getX509Certificates().add(test0Cert);
  }

  protected HttpHeaders test0SSLHeadersVerificationSuccess() {
    return test0SSLHeaders(true, null);
  }

  protected HttpHeaders test0SSLHeadersVerificationFailed(String verificationError) {
    return test0SSLHeaders(false, verificationError);
  }

  private HttpHeaders test0SSLHeaders(boolean verified, String verificationError) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader(),
        TEST_0_CERT_STRING_NGINX);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SUBJECT.getHeader(),
        TEST_0_SUBJECT);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.ISSUER.getHeader(),
        TEST_0_ISSUER);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SERIAL.getHeader(),
        TEST_0_SERIAL);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.V_START.getHeader(),
        TEST_0_V_START);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.V_END.getHeader(),
        TEST_0_V_END);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.PROTOCOL.getHeader(), "TLS");

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SERVER_NAME.getHeader(),
        "serverName");

    if (verified) {
      headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader(),
          "SUCCESS");
    } else {
      headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader(),
          "FAILED:" + verificationError);
    }

    return headers;
  }

  protected void mockHttpRequestWithTest0SSLHeaders(HttpServletRequest request) {
    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader()))
      .thenReturn(TEST_0_CERT_STRING_NGINX);

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.SUBJECT.getHeader()))
      .thenReturn(TEST_0_SUBJECT);

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.ISSUER.getHeader()))
      .thenReturn(TEST_0_ISSUER);

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.SERIAL.getHeader()))
      .thenReturn(TEST_0_SERIAL);

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.V_START.getHeader()))
      .thenReturn(TEST_0_V_START);

    Mockito
      .when(
          request.getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.V_END.getHeader()))
      .thenReturn(TEST_0_V_END);

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.PROTOCOL.getHeader()))
      .thenReturn("TLS");

    // Mockito
    // .when(request
    // .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.SERVER_NAME.getHeader()))
    // .thenReturn("serverName");

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader()))
      .thenReturn("SUCCESS");

  }
}
