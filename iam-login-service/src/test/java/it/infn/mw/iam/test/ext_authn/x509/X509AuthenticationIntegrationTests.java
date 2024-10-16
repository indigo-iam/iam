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

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_ERROR_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY;
import static it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter.X509_AUTHN_REQUESTED_PARAM;
import static it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter.X509_CAN_LOGIN_KEY;
import static it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter.X509_CREDENTIAL_SESSION_KEY;
import static java.lang.Boolean.TRUE;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import junit.framework.AssertionFailedError;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class X509AuthenticationIntegrationTests extends X509TestSupport {

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private IamX509CertificateRepository iamX509CertificateRepo;

  @Autowired
  private MockMvc mvc;

  @Test
  public void testX509AuthenticationSuccessUserNotFound() throws Exception {
    mvc.perform(MockMvcRequestBuilders.get("/").headers(test0SSLHeadersVerificationSuccess()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("http://localhost/login"));
  }

  @Test
  public void testX509AuthenticationSuccessButNotRequestedLeadsToLoginPage() throws Exception {

    Instant now = Instant.now();

    IamAccount testAccount = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    linkTest0CertificateToAccount(testAccount);

    iamAccountRepo.save(testAccount);

    IamAccount resolvedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(
          () -> new AssertionError("Expected test user linked with subject " + TEST_0_SUBJECT));

    assertThat(resolvedAccount.getUsername(), equalTo("test"));

    mvc.perform(get("/").headers(test0SSLHeadersVerificationSuccess()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("http://localhost/login"))
      .andExpect(request().sessionAttribute(X509_CREDENTIAL_SESSION_KEY, not(nullValue())))
      .andExpect(request().attribute(X509_CAN_LOGIN_KEY, is(TRUE)));

    mvc
      .perform(get("/dashboard").param(X509_AUTHN_REQUESTED_PARAM, "true")
        .headers(test0SSLHeadersVerificationSuccess()))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(authenticated().withUsername("test"));

    resolvedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(
          () -> new AssertionError("Expected test user linked with subject " + TEST_0_SUBJECT));

    // Check that last login time is updated when loggin in with X.509 credentials
    assertThat(resolvedAccount.getLastLoginTime().toInstant(), greaterThan(now));

  }

  @Test
  public void testX509AuthenticationVerifyFailedLeadsToLoginPage() throws Exception {

    IamAccount testAccount = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    linkTest0CertificateToAccount(testAccount);

    iamAccountRepo.save(testAccount);

    IamAccount resolvedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(
          () -> new AssertionError("Expected test user linked with subject " + TEST_0_SUBJECT));

    assertThat(resolvedAccount.getUsername(), equalTo("test"));

    mvc
      .perform(MockMvcRequestBuilders.get("/")
        .headers(test0SSLHeadersVerificationFailed("verification failed")))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("http://localhost/login"));
  }


  @Test
  public void testX509AccountLinkingRequiresAuthenticatedUser() throws Exception {
    mvc.perform(post("/iam/account-linking/X509").with(csrf().asHeader()))
      .andExpect(status().isUnauthorized());
  }


  @Test
  @WithMockUser(username = "test")
  public void testX509AccountLinkingWithoutCertFails() throws Exception {

    String errorMessage = "No X.509 credential found in session for user 'test'";
    mvc.perform(post("/iam/account-linking/X509").with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY, equalTo(errorMessage)));
  }

  @Test
  public void testx509AccountLinking() throws Exception {

    MockHttpSession session = loginAsTestUserWithTest0Cert(mvc);
    IamX509AuthenticationCredential credential =
        (IamX509AuthenticationCredential) session.getAttribute(X509_CREDENTIAL_SESSION_KEY);

    assertThat(credential.getSubject(), equalTo(TEST_0_SUBJECT));
    assertThat(credential.getIssuer(), equalTo(TEST_0_ISSUER));

    String confirmationMessage =
        String.format("Certificate '%s' linked succesfully", credential.getSubject());

    mvc.perform(post("/iam/account-linking/X509").session(session).with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY, equalTo(confirmationMessage)));

    Optional<IamAccount> linkedUser =
        iamX509CertificateRepo.findBySubjectDn(TEST_0_SUBJECT).stream().findFirst();
    assertThat(linkedUser.isPresent(), is(true));
    assertThat(linkedUser.get().getUsername(), is("test"));

    Optional<IamX509Certificate> test0Cert = iamX509CertificateRepo.findBySubjectDnAndIssuerDn(TEST_0_SUBJECT, TEST_0_ISSUER);
    assertThat(test0Cert.isPresent(), is(true));

    IamAccount linkedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(() -> new AssertionFailedError("Expected user linked to certificate not found"));

    Date lastUpdateTime = linkedAccount.getLastUpdateTime();
    assertThat(linkedAccount.getUsername(), equalTo("test"));

    // This is to "update" the linked certificate
    mvc.perform(post("/iam/account-linking/X509").session(session).with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY, equalTo(confirmationMessage)));

    linkedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(() -> new AssertionFailedError("Expected user linked to certificate not found"));

    assertThat(linkedAccount.getLastUpdateTime().after(lastUpdateTime), is(true));
    assertThat(linkedAccount.getX509Certificates().size(), is(1));

    MockHttpSession session1 = loginAsTestUserWithTest1Cert(mvc);

    IamX509AuthenticationCredential credential1 =
        (IamX509AuthenticationCredential) session1.getAttribute(X509_CREDENTIAL_SESSION_KEY);

    assertThat(credential1.getSubject(), equalTo(TEST_0_SUBJECT));
    assertThat(credential1.getIssuer(), equalTo(TEST_NEW_ISSUER));

    String confirmationMsg =
        String.format("Certificate '%s' linked succesfully", credential1.getSubject());

    mvc.perform(post("/iam/account-linking/X509").session(session1).with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY, equalTo(confirmationMsg)));

    Optional<IamX509Certificate> testCert1 = iamX509CertificateRepo.findBySubjectDnAndIssuerDn(TEST_0_SUBJECT, TEST_0_ISSUER);
    assertThat(testCert1.isPresent(), is(true));
    assertThat(testCert1.get().getAccount().getUsername(), is("test"));
    
    Optional<IamX509Certificate> testCert2 = iamX509CertificateRepo.findBySubjectDnAndIssuerDn(TEST_0_SUBJECT, TEST_NEW_ISSUER);
    assertThat(testCert2.isPresent(), is(true));
    assertThat(testCert2.get().getAccount().getUsername(), is("test"));

    // Try to link cert to another user
    MockHttpSession session2 = loginAsTest100UserWithTest0Cert(mvc);
    IamX509AuthenticationCredential credential2 =
        (IamX509AuthenticationCredential) session2.getAttribute(X509_CREDENTIAL_SESSION_KEY);

    assertThat(credential2.getSubject(), equalTo(TEST_0_SUBJECT));
    assertThat(credential2.getIssuer(), equalTo(TEST_0_ISSUER));

    String expectedErrorMessage =
        String.format("X.509 credential with subject '%s' is already linked to another user",
            credential2.getSubject());

    mvc.perform(post("/iam/account-linking/X509").session(session2).with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY, equalTo(expectedErrorMessage)));
  }

  @Test
  public void testUpdateCertWithSameIssuerAndSubjectButDifferentPem() throws Exception {

    IamAccount account = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionFailedError("Account not found"));
    account.linkX509Certificates(singletonList(OLD_TEST_0_IAM_X509_CERT));

    String oldPemCert = OLD_TEST_0_IAM_X509_CERT.getCertificate();

    MockHttpSession session = loginAsTestUserWithTest0Cert(mvc);
    IamX509AuthenticationCredential credential =
        (IamX509AuthenticationCredential) session.getAttribute(X509_CREDENTIAL_SESSION_KEY);

    String confirmationMessage =
        String.format("Certificate '%s' linked succesfully", credential.getSubject());

    mvc.perform(post("/iam/account-linking/X509").session(session).with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY, equalTo(confirmationMessage)));

    Optional<IamX509Certificate> testCert =
        iamX509CertificateRepo.findBySubjectDnAndIssuerDn(TEST_0_SUBJECT, TEST_0_ISSUER);
    assertThat(testCert.isPresent(), is(true));
    assertThat(
        account.getX509Certificates()
          .stream()
          .anyMatch(cert -> cert.getCertificate().equals(testCert.get().getCertificate())),
        is(true));

    assertThat(account.getX509Certificates()
      .stream()
      .anyMatch(cert -> cert.getCertificate().equals(oldPemCert)), is(false));
  }

  @Test
  public void testx509AccountLinkingWithDifferentSubjectAndIssuer() throws Exception {

    MockHttpSession session = loginAsTestUserWithTest0Cert(mvc);
    IamX509AuthenticationCredential credential =
        (IamX509AuthenticationCredential) session.getAttribute(X509_CREDENTIAL_SESSION_KEY);

    assertThat(credential.getSubject(), equalTo(TEST_0_SUBJECT));

    String confirmationMessage =
        String.format("Certificate '%s' linked succesfully", credential.getSubject());

    mvc.perform(post("/iam/account-linking/X509").session(session).with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY, equalTo(confirmationMessage)));

    IamAccount linkedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(() -> new AssertionFailedError("Expected user linked to certificate not found"));

    assertThat(linkedAccount.getUsername(), equalTo("test"));

    MockHttpSession session1 = loginAsTestUserWithTest2Cert(mvc);

    IamX509AuthenticationCredential credential1 =
        (IamX509AuthenticationCredential) session1.getAttribute(X509_CREDENTIAL_SESSION_KEY);

    assertThat(credential1.getSubject(), equalTo(TEST_1_SUBJECT));
    assertThat(credential1.getIssuer(), equalTo(TEST_NEW_ISSUER));

    String confirmationMsg =
        String.format("Certificate '%s' linked succesfully", credential1.getSubject());

    mvc.perform(post("/iam/account-linking/X509").session(session1).with(csrf().asHeader()))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("/dashboard"))
      .andExpect(
          flash().attribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY, equalTo(confirmationMsg)));

    linkedAccount = iamAccountRepo.findByCertificateSubject(TEST_1_SUBJECT)
      .orElseThrow(() -> new AssertionFailedError("Expected user linked to certificate not found"));

    assertThat(linkedAccount.getX509Certificates().size(), is(2));
  }

  @Test
  @WithMockUser(username = "test")
  public void x509AccountUnlinkWorks() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    linkTest0CertificateToAccount(user);

    iamAccountRepo.save(user);

    IamAccount linkedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(() -> new AssertionError(
          "Expected test user linked with certificate subject " + TEST_0_SUBJECT));

    assertThat(linkedAccount.getUsername(), equalTo("test"));

    mvc
      .perform(delete("/iam/account-linking/X509").param("certificateSubject", TEST_0_SUBJECT)
        .with(csrf().asHeader()))
      .andDo(print())
      .andExpect(status().isNoContent());

    iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT).ifPresent(a -> {
      throw new AssertionError(
          "Found unexpected user linked with certificate subject " + TEST_0_SUBJECT);
    });

  }

  @Test
  @WithMockUser(username = "test")
  public void x509AccountUnlinkSuccedsSilentlyForUnlinkedAccount() throws Exception {
    iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT).ifPresent(a -> {
      throw new AssertionError(
          "Found unexpected user linked with certificate subject " + TEST_0_SUBJECT);
    });

    mvc
      .perform(delete("/iam/account-linking/X509").param("certificateSubject", TEST_0_SUBJECT)
        .with(csrf().asHeader()))
      .andExpect(status().isNoContent());

    iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT).ifPresent(a -> {
      throw new AssertionError(
          "Found unexpected user linked with certificate subject " + TEST_0_SUBJECT);
    });
  }

  @Test
  public void x509AccountUnlinkingFailsForUnauthenticatedUsers() throws Exception {
    mvc
      .perform(delete("/iam/account-linking/X509").param("certificateSubject", TEST_0_SUBJECT)
        .with(csrf().asHeader()))
      .andDo(print())
      .andExpect(status().isUnauthorized());
  }

  @Test
  public void testx509AuthNFailsIfDisabledUser() throws Exception {

    IamAccount testAccount = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    linkTest0CertificateToAccount(testAccount);

    iamAccountRepo.save(testAccount);

    IamAccount resolvedAccount = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(
          () -> new AssertionError("Expected test user linked with subject " + TEST_0_SUBJECT));

    assertThat(resolvedAccount.getUsername(), equalTo("test"));

    resolvedAccount.setActive(false);

    mvc.perform(get("/dashboard").param(X509_AUTHN_REQUESTED_PARAM, "true"))
      .andExpect(status().is3xxRedirection())
      .andExpect(redirectedUrl("http://localhost/login"));

    resolvedAccount.setActive(true);

  }

  @Test
  public void testHashAndEqualsMethods() {

    HashSet<IamX509Certificate> set1 =
        new HashSet<IamX509Certificate>(Arrays.asList(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT));
    assertThat(set1.size(), is(2));
    assertNotEquals(TEST_0_IAM_X509_CERT.hashCode(), TEST_1_IAM_X509_CERT.hashCode());
    assertEquals(set1.hashCode(),
        TEST_0_IAM_X509_CERT.hashCode() + TEST_1_IAM_X509_CERT.hashCode());
    assertNotEquals(TEST_0_IAM_X509_CERT, TEST_1_IAM_X509_CERT);

    HashSet<IamX509Certificate> set2 =
        new HashSet<IamX509Certificate>(Arrays.asList(TEST_0_IAM_X509_CERT, TEST_2_IAM_X509_CERT));
    assertThat(set2.size(), is(1));
    assertEquals(TEST_0_IAM_X509_CERT.hashCode(), TEST_2_IAM_X509_CERT.hashCode());
    assertEquals(set2.hashCode(), TEST_0_IAM_X509_CERT.hashCode());
    assertEquals(TEST_0_IAM_X509_CERT, TEST_2_IAM_X509_CERT);

  }

}
