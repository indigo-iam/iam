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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
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
  public static final String OLD_TEST_0_CERT_PATH = "src/test/resources/x509/oldtest0.cert.pem";
  public static final String OLD_TEST_0_KEY_PATH = "src/test/resources/x509/oldtest0.key.pem";
  public static final String TEST_0_KEY_PATH = "src/test/resources/x509/test0.key.pem";
  public static final String TEST_0_DER_CERT_PATH = "src/test/resources/x509/test0.cert.der";

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

  public static final String TEST_2_CERT_PATH = "src/test/resources/x509/test2.cert.pem";
  public static final String TEST_2_SUBJECT = "CN=test01,O=IGI,C=IT";
  public static final String TEST_2_ISSUER = "CN=test01,O=IGI,C=IT";
  public static final String TEST_2_SERIAL = "10";
  public static final String TEST_2_V_START = "Jul 01 13:28:00 2025 GMT";
  public static final String TEST_2_V_END = "Jun 29 13:28:00 2035 GMT";

  public static final String TEST_NEW_ISSUER = "CN=Test1 CA,O=IGI,C=IT";

  public static final String RCAUTH_CA_CERT_PATH = "src/test/resources/x509/rcauth-mock-ca.p12";
  public static final String RCAUTH_CA_CERT_PASSWORD = "pass123";

  public static final String RCAUTH_CA_SUBJECT = "CN=RCAuth Mock CA,O=INDIGO-IAM,C=IT";

  protected IamX509Certificate TEST_3_IAM_X509_CERT;

  public static final String TEST_0_CERT_LABEL = "TEST 0 cert label";
  public static final String TEST_1_CERT_LABEL = "TEST 1 cert label";
  public static final String TEST_2_CERT_LABEL = "TEST 2 cert label";
  public static final String OLD_TEST_0_CERT_LABEL = "Old TEST 0 cert label";

  public static final String TEST_USERNAME = "test";
  public static final String TEST_100_USERNAME = "test_100";
  public static final String TEST_PASSWORD = "password";

  protected X509Credential RCAUTH_CA_CRED;

  // TEST 0

  protected String getTest0CertString() throws IOException {

    return new String(Files.readAllBytes(Paths.get(TEST_0_CERT_PATH)));
  }

  protected X509Certificate getTest0Cert() throws IOException {
    return CertificateUtils.loadCertificate(
        new ByteArrayInputStream(getTest0CertString().getBytes(StandardCharsets.US_ASCII)),
        Encoding.PEM);
  }

  protected IamX509Certificate getTest0Cert(Instant instant) throws IOException {

    Date now = Date.from(instant);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setCertificate(getTest0CertString());
    cert.setSubjectDn(TEST_0_SUBJECT);
    cert.setIssuerDn(TEST_0_ISSUER);
    cert.setLabel(TEST_0_CERT_LABEL);
    cert.setPrimary(false);
    cert.setCreationTime(now);
    cert.setLastUpdateTime(now);
    return cert;
  }

  protected byte[] getTest0DerCertBytes() throws IOException {

    return Files.readAllBytes(Paths.get(TEST_0_DER_CERT_PATH));
  }

  protected X509Certificate getTest0DerCert() throws IOException {

    return CertificateUtils.loadCertificate(new ByteArrayInputStream(getTest0DerCertBytes()),
        Encoding.DER);
  }

  // This is how NGINX encodes certificate in the header when $ssl_client_cert is used
  protected String getTest0CertNginx() throws IOException {

    return getTest0CertString().replace('\n', '\t');
  }

  // This is how NGINX encodes certificate in the header when $ssl_client_escaped_cert is used
  protected String getTest0CertNginxEscaped() throws IOException {

    return URLEncoder.encode(getTest0CertString(), StandardCharsets.UTF_8);
  }

  // This is how HAProxy encodes certificate in the header when [ssl_c_der,base64] is used
  protected String getTest0CertHaProxy() throws IOException {

    return Base64.getEncoder().encodeToString(getTest0DerCertBytes());
  }

  protected PEMCredential getTest0PemCredential()
      throws KeyStoreException, CertificateException, IOException {

    return new PEMCredential(TEST_0_KEY_PATH, TEST_0_CERT_PATH, "pass".toCharArray());
  }

  // Old Test 0

  protected String getOldTest0CertString() throws IOException {

    return new String(Files.readAllBytes(Paths.get(OLD_TEST_0_CERT_PATH)));
  }

  protected X509Certificate getOldTest0Cert() throws IOException {
    return CertificateUtils.loadCertificate(
        new ByteArrayInputStream(getOldTest0CertString().getBytes(StandardCharsets.US_ASCII)),
        Encoding.PEM);
  }

  protected IamX509Certificate getOldTest0Cert(Instant instant) throws IOException {

    Date now = Date.from(instant);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setCertificate(getOldTest0CertString());
    cert.setSubjectDn(TEST_0_SUBJECT);
    cert.setIssuerDn(TEST_0_ISSUER);
    cert.setLabel(OLD_TEST_0_CERT_LABEL);
    cert.setPrimary(false);
    cert.setCreationTime(now);
    cert.setLastUpdateTime(now);
    return cert;
  }

  // Test 1

  protected String getTest1CertString() throws IOException {

    return new String(Files.readAllBytes(Paths.get(TEST_1_CERT_PATH)));
  }

  protected X509Certificate getTest1Cert() throws IOException {
    return CertificateUtils.loadCertificate(
        new ByteArrayInputStream(getTest1CertString().getBytes(StandardCharsets.US_ASCII)),
        Encoding.PEM);
  }

  protected IamX509Certificate getTest1Cert(Instant instant) throws IOException {

    Date now = Date.from(instant);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setCertificate(getTest1CertString());
    cert.setSubjectDn(TEST_1_SUBJECT);
    cert.setIssuerDn(TEST_1_ISSUER);
    cert.setLabel(TEST_1_CERT_LABEL);
    cert.setPrimary(false);
    cert.setCreationTime(now);
    cert.setLastUpdateTime(now);
    return cert;
  }

  // This is how NGINX encodes certificate in the header when $ssl_client_cert is used
  protected String getTest1CertNginx() throws IOException {

    return getTest1CertString().replace('\n', '\t');
  }

  // Test 2

  protected String getTest2CertString() throws IOException {

    return new String(Files.readAllBytes(Paths.get(TEST_2_CERT_PATH)));
  }

  protected X509Certificate getTest2Cert() throws IOException {
    return CertificateUtils.loadCertificate(
        new ByteArrayInputStream(getTest2CertString().getBytes(StandardCharsets.US_ASCII)),
        Encoding.PEM);
  }

  // This is how NGINX encodes certificate in the header when $ssl_client_cert is used
  protected String getTest2CertNginx() throws IOException {

    return getTest2CertString().replace('\n', '\t');
  }

  protected IamX509Certificate getTest2Cert(Instant instant) throws IOException {

    Date now = Date.from(instant);
    IamX509Certificate cert = new IamX509Certificate();
    // Certificate of Test 1!!
    cert.setCertificate(getTest1CertString());
    // Subject of Test 0!!
    cert.setSubjectDn(TEST_0_SUBJECT);
    // Issuer DN of Test 1!!
    cert.setIssuerDn(TEST_1_ISSUER);
    // Certificate label of Test 1!!
    cert.setLabel(TEST_1_CERT_LABEL);
    cert.setPrimary(false);
    cert.setCreationTime(now);
    cert.setLastUpdateTime(now);
    return cert;
  }

  // Test 3

  protected IamX509Certificate getTest3Cert(Instant instant) throws IOException {

    Date now = Date.from(instant);
    IamX509Certificate cert = new IamX509Certificate();
    cert.setCertificate(getTest2CertString());
    cert.setSubjectDn(TEST_2_SUBJECT);
    cert.setIssuerDn(TEST_2_ISSUER);
    cert.setLabel(TEST_2_CERT_LABEL);
    cert.setPrimary(false);
    cert.setCreationTime(now);
    cert.setLastUpdateTime(now);
    return cert;
  }

  // RCAUTH CA CRED
  protected X509Credential getRCAuthCaCred() throws KeyStoreException, IOException {

    return new KeystoreCredential(RCAUTH_CA_CERT_PATH, RCAUTH_CA_CERT_PASSWORD.toCharArray(),
        RCAUTH_CA_CERT_PASSWORD.toCharArray(), null, "PKCS12");
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

  protected MockHttpSession loginAsTest100UserWithTest0Cert(MockMvc mvc) throws Exception {

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
        .param("username", TEST_100_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/"))
      .andExpect(authenticated().withUsername("test_100"))
      .andReturn()
      .getRequest()
      .getSession();

    return session;
  }

  protected MockHttpSession loginAsTestUserWithTest1Cert(MockMvc mvc) throws Exception {

    MockHttpSession session =
        (MockHttpSession) mvc.perform(get("/").headers(test1SSLHeadersVerificationSuccess()))
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

  protected MockHttpSession loginAsTestUserWithTest2Cert(MockMvc mvc) throws Exception {

    MockHttpSession session =
        (MockHttpSession) mvc.perform(get("/").headers(test2SSLHeadersVerificationSuccess()))
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

  protected void linkTest1CertificateToAccount(IamAccount account, Instant instant)
      throws IOException {
    IamX509Certificate test1Cert = new IamX509Certificate();
    test1Cert.setPrimary(false);

    test1Cert.setCertificate(getTest1CertString());
    test1Cert.setSubjectDn(TEST_1_SUBJECT);
    test1Cert.setIssuerDn(TEST_1_ISSUER);
    test1Cert.setLabel(TEST_1_CERT_LABEL);

    Date now = Date.from(instant);

    test1Cert.setCreationTime(now);
    test1Cert.setLastUpdateTime(now);

    test1Cert.setAccount(account);
    account.getX509Certificates().add(test1Cert);
  }

  protected void linkTest0CertificateToAccount(IamAccount account, Instant instant)
      throws IOException {
    IamX509Certificate test0Cert = new IamX509Certificate();
    test0Cert.setPrimary(true);

    Date now = Date.from(instant);

    test0Cert.setCertificate(getTest0CertString());
    test0Cert.setSubjectDn(TEST_0_SUBJECT);
    test0Cert.setIssuerDn(TEST_0_ISSUER);
    test0Cert.setLabel(TEST_0_CERT_LABEL);

    test0Cert.setCreationTime(now);
    test0Cert.setLastUpdateTime(now);

    test0Cert.setAccount(account);
    account.getX509Certificates().add(test0Cert);
  }

  protected void linkCertificateToAccount(IamAccount account, String subjectDN, String issuerDN,
      String label, Instant instant) {

    IamX509Certificate cert = new IamX509Certificate();
    cert.setPrimary(false);
    cert.setSubjectDn(subjectDN);
    cert.setIssuerDn(issuerDN);
    cert.setLabel(label);

    Date now = Date.from(instant);

    cert.setCreationTime(now);
    cert.setLastUpdateTime(now);

    cert.setAccount(account);
    account.getX509Certificates().add(cert);
  }

  protected HttpHeaders test0SSLHeadersVerificationSuccess() throws IOException {
    return test0SSLHeaders(true, null);
  }

  protected HttpHeaders test1SSLHeadersVerificationSuccess() throws IOException {
    return test1SSLHeaders(true, null);
  }

  protected HttpHeaders test2SSLHeadersVerificationSuccess() throws IOException {
    return test2SSLHeaders(true, null);
  }

  protected HttpHeaders test0SSLHeadersVerificationFailed(String verificationError)
      throws IOException {
    return test0SSLHeaders(false, verificationError);
  }

  private HttpHeaders test0SSLHeaders(boolean verified, String verificationError)
      throws IOException {
    HttpHeaders headers = new HttpHeaders();
    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader(),
        getTest0CertNginx());

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

  private HttpHeaders test2SSLHeaders(boolean verified, String verificationError)
      throws IOException {

    HttpHeaders headers = new HttpHeaders();
    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader(),
        getTest1CertNginx());

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SUBJECT.getHeader(),
        TEST_1_SUBJECT);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.ISSUER.getHeader(),
        TEST_NEW_ISSUER);

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

  private HttpHeaders test1SSLHeaders(boolean verified, String verificationError)
      throws IOException {

    HttpHeaders headers = new HttpHeaders();
    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader(),
        getTest1CertNginx());

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SUBJECT.getHeader(),
        TEST_0_SUBJECT);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.ISSUER.getHeader(),
        TEST_NEW_ISSUER);

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

  protected void mockHttpRequestWithTest0SSLHeaders(HttpServletRequest request) throws IOException {
    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader()))
      .thenReturn(getTest0CertNginx());

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

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader()))
      .thenReturn("SUCCESS");

  }

  protected void mockHttpRequestWithTest0SSLHeadersNginxNew(HttpServletRequest request)
      throws IOException {

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader()))
      .thenReturn(getTest0CertNginxEscaped());

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

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader()))
      .thenReturn("SUCCESS");

  }

  protected void mockHttpRequestWithTest0SSLHeadersHAProxy(HttpServletRequest request)
      throws IOException {

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader()))
      .thenReturn(getTest0CertHaProxy());

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

    Mockito
      .when(request
        .getHeader(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader()))
      .thenReturn("X509_V_OK");

  }
}
