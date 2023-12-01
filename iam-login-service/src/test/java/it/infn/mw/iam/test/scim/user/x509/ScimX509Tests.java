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
package it.infn.mw.iam.test.scim.user.x509;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
public class ScimX509Tests extends X509TestSupport implements ScimConstants {

  public static final Logger LOG = LoggerFactory.getLogger(ScimX509Tests.class);
  public static final String JP_INDIGO_USER = "$." + INDIGO_USER_SCHEMA;

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private ObjectMapper mapper;
  
  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }
  
  @After
  public void teardown() throws Exception {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testNoScimX509ForAccountWithoutCertificates() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    mvc.perform(get("/scim/Users/{id}", user.getUuid())).andExpect(status().isOk()).andExpect(
        jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).doesNotExist());

  }

  @Test
  public void testScimX509Answer() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    linkTest0CertificateToAccount(user);

    iamAccountRepo.save(user);

    mvc.perform(get("/scim/Users/{id}", user.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).isArray())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).value(hasSize(1)))
      .andExpect(jsonPath("$.%s.certificates[0].created", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates[0].lastModified", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates[0].subjectDn", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_0_SUBJECT)))
      .andExpect(jsonPath("$.%s.certificates[0].issuerDn", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_0_ISSUER)))
      .andExpect(jsonPath("$.%s.certificates[0].pemEncodedCertificate", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_0_CERT_STRING)))
      .andExpect(jsonPath("$.%s.certificates[0].display", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_0_CERT_LABEL)))
      .andExpect(jsonPath("$.%s.certificates[0].primary", INDIGO_USER_SCHEMA).value(equalTo(true)));
  }

  @Test
  public void testScimX509AnswerMultipleCerts() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    linkTest0CertificateToAccount(user);
    linkTest1CertificateToAccount(user);

    iamAccountRepo.save(user);

    mvc.perform(get("/scim/Users/{id}", user.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).isArray())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).value(hasSize(2)));
  }

  @Test
  public void testScimCreateUserWithCertSucceeds() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_1_CERT_LABEL)
      .pemEncodedCertificate(TEST_1_CERT_STRING)
      .build();

    ScimUser user = ScimUser.builder("user_with_x509_cert")
      .buildEmail("user_with_x509_cert@test.org")
      .buildName("User", "With cert")
      .active(true)
      .addX509Certificate(cert)
      .build();


    String scimUserString = mapper.writeValueAsString(user);

    mvc
      .perform(MockMvcRequestBuilders.post("/scim/Users")
        .content(scimUserString)
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isCreated())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).isArray())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).value(hasSize(1)))
      .andExpect(jsonPath("$.%s.certificates[0].created", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates[0].lastModified", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates[0].subjectDn", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_SUBJECT)))
      .andExpect(jsonPath("$.%s.certificates[0].issuerDn", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_ISSUER)))
      .andExpect(jsonPath("$.%s.certificates[0].pemEncodedCertificate", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_CERT_STRING)))
      .andExpect(jsonPath("$.%s.certificates[0].display", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_CERT_LABEL)))
      .andExpect(jsonPath("$.%s.certificates[0].primary", INDIGO_USER_SCHEMA).value(equalTo(true)));

  }

  @Test
  public void testScimCreateUserWithCertAndProvidedSubjectInfoSucceeds() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_1_CERT_LABEL)
      .pemEncodedCertificate(TEST_1_CERT_STRING)
      .subjectDn("a fake subject")
      .issuerDn("a fake issuer")
      .build();

    ScimUser user = ScimUser.builder("user_with_x509_cert")
      .buildEmail("user_with_x509_cert@test.org")
      .buildName("User", "With cert")
      .active(true)
      .addX509Certificate(cert)
      .build();


    String scimUserString = mapper.writeValueAsString(user);

    mvc
      .perform(MockMvcRequestBuilders.post("/scim/Users")
        .content(scimUserString)
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isCreated())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).isArray())
      .andExpect(jsonPath("$.%s.certificates", INDIGO_USER_SCHEMA).value(hasSize(1)))
      .andExpect(jsonPath("$.%s.certificates[0].created", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates[0].lastModified", INDIGO_USER_SCHEMA).exists())
      .andExpect(jsonPath("$.%s.certificates[0].subjectDn", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_SUBJECT)))
      .andExpect(jsonPath("$.%s.certificates[0].issuerDn", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_ISSUER)))
      .andExpect(jsonPath("$.%s.certificates[0].pemEncodedCertificate", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_CERT_STRING)))
      .andExpect(jsonPath("$.%s.certificates[0].display", INDIGO_USER_SCHEMA)
        .value(equalTo(TEST_1_CERT_LABEL)))
      .andExpect(jsonPath("$.%s.certificates[0].primary", INDIGO_USER_SCHEMA).value(equalTo(true)));

  }

  @Test
  public void testScimCreateUserWithInvalidCertFails() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_1_CERT_LABEL)
      .pemEncodedCertificate("whatever")
      .build();

    ScimUser user = ScimUser.builder("user_with_x509_cert")
      .buildEmail("user_with_x509_cert@test.org")
      .buildName("User", "With cert")
      .active(true)
      .addX509Certificate(cert)
      .build();


    String scimUserString = mapper.writeValueAsString(user);

    mvc
      .perform(MockMvcRequestBuilders.post("/scim/Users")
        .content(scimUserString)
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status").exists())
      .andExpect(jsonPath("$.status").value(equalTo("400")))
      .andExpect(jsonPath("$.schemas").exists())
      .andExpect(jsonPath("$.schemas")
        .value(Matchers.contains("urn:ietf:params:scim:api:messages:2.0:Error")))
      .andExpect(jsonPath("$.detail").exists())
      .andExpect(jsonPath("$.detail").value(containsString("Error parsing certificate chain")));
  }

  @Test
  public void testScimCreateUserWithBoundCertFails() throws Exception {
    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_0_CERT_LABEL)
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .build();

    ScimUser user = ScimUser.builder("user_with_x509_cert")
      .buildEmail("user_with_x509_cert@test.org")
      .buildName("User", "With cert")
      .active(true)
      .addX509Certificate(cert)
      .build();

    mvc
      .perform(MockMvcRequestBuilders.post("/scim/Users")
        .content(mapper.writeValueAsString(user))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isCreated());

    ScimUser anotherUser = ScimUser.builder("another_user_with_x509_cert")
      .buildEmail("another_user_with_x509_cert@test.org")
      .buildName("Another User", "With cert")
      .active(true)
      .addX509Certificate(cert)
      .build();

    mvc
      .perform(MockMvcRequestBuilders.post("/scim/Users")
        .content(mapper.writeValueAsString(anotherUser))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.status").exists())
      .andExpect(jsonPath("$.status").value(equalTo("409")))
      .andExpect(jsonPath("$.schemas").exists())
      .andExpect(jsonPath("$.schemas")
        .value(Matchers.contains("urn:ietf:params:scim:api:messages:2.0:Error")))
      .andExpect(jsonPath("$.detail").exists())
      .andExpect(jsonPath("$.detail").value(containsString(
          "X509 certificate with subject 'CN=test0,O=IGI,C=IT' is already bound to another user")));

  }

  @Test
  public void testScimAddCertificateSuccess() throws Exception {
    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_0_CERT_LABEL)
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .build();

    IamAccount testUser = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    ScimUser user = ScimUser.builder().addX509Certificate(cert).build();

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder().add(user).build();

    mvc
      .perform(patch("/scim/Users/{id}", testUser.getUuid())
        .content(mapper.writeValueAsString(patchRequest)).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNoContent());

    testUser = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    assertThat(testUser.getUsername(), equalTo(TEST_USERNAME));
  }
  
  @Test
  public void testScimAddCertificateFailureInvalidCertificate() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_0_CERT_LABEL)
      .pemEncodedCertificate("whatever")
      .build();

    IamAccount testUser = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().addX509Certificate(cert).build())
      .build();

    mvc
      .perform(patch("/scim/Users/{id}", testUser.getUuid())
        .content(mapper.writeValueAsString(patchRequest)).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status").exists())
      .andExpect(jsonPath("$.status").value(equalTo("400")))
      .andExpect(jsonPath("$.schemas").exists())
      .andExpect(jsonPath("$.schemas")
        .value(Matchers.contains("urn:ietf:params:scim:api:messages:2.0:Error")))
      .andExpect(jsonPath("$.detail").exists())
      .andExpect(jsonPath("$.detail").value(containsString("Error parsing certificate chain")));
  }

  @Test
  public void testScimAddCertificateFailureCertificateAlreadyBound() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_0_CERT_LABEL)
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .build();

    ScimUser user = ScimUser.builder("user_with_x509_cert")
      .buildEmail("user_with_x509_cert@test.org")
      .buildName("User", "With cert")
      .active(true)
      .addX509Certificate(cert)
      .build();

    mvc
      .perform(post("/scim/Users")
        .content(mapper.writeValueAsString(user))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isCreated());

    IamAccount testUser = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));


    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .add(ScimUser.builder().addX509Certificate(cert).build())
      .build();

    mvc
      .perform(patch("/scim/Users/{id}", testUser.getUuid())
        .content(mapper.writeValueAsString(patchRequest)).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.status").exists())
      .andExpect(jsonPath("$.status").value(equalTo("409")))
      .andExpect(jsonPath("$.schemas").exists())
      .andExpect(jsonPath("$.schemas")
        .value(Matchers.contains("urn:ietf:params:scim:api:messages:2.0:Error")))
      .andExpect(jsonPath("$.detail").exists())
      .andExpect(jsonPath("$.detail").value(containsString(
          "X509 certificate with subject 'CN=test0,O=IGI,C=IT' is already bound to another user")));
  }

  @Test
  public void testScimRemoveCertificateSuccess() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_0_CERT_LABEL)
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .build();

    ScimUser user = ScimUser.builder("user_with_x509_cert")
      .buildEmail("user_with_x509_cert@test.org")
      .buildName("User", "With cert")
      .active(true)
      .addX509Certificate(cert)
      .build();

    mvc
      .perform(MockMvcRequestBuilders.post("/scim/Users")
        .content(mapper.writeValueAsString(user))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isCreated());

    IamAccount account = iamAccountRepo.findByCertificateSubject(TEST_0_SUBJECT)
      .orElseThrow(() -> new AssertionError(
          "Expected account bound to '" + TEST_0_SUBJECT + "' certificate not found"));

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .remove(ScimUser.builder().addX509Certificate(cert).build())
      .build();

    mvc
      .perform(patch("/scim/Users/{id}", account.getUuid())
        .content(mapper.writeValueAsString(patchRequest)).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNoContent());

    iamAccountRepo.findByCertificate(TEST_0_SUBJECT).ifPresent(a -> {
      throw new AssertionError("Found unexpected account bound to '" + TEST_0_SUBJECT
          + "' certificate: " + a.getUsername());
    });
  }

  @Test
  public void testScimRemoveUnboundCertificateYeldsa204() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(TEST_0_CERT_LABEL)
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .build();

    iamAccountRepo.findByCertificate(TEST_0_SUBJECT).ifPresent(a -> {
      throw new AssertionError("Found unexpected account bound to '" + TEST_0_SUBJECT
          + "' certificate: " + a.getUsername());
    });

    IamAccount testUser = iamAccountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    ScimUserPatchRequest patchRequest = ScimUserPatchRequest.builder()
      .remove(ScimUser.builder().addX509Certificate(cert).build())
      .build();

    mvc
      .perform(patch("/scim/Users/{id}", testUser.getUuid())
        .content(mapper.writeValueAsString(patchRequest)).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isNoContent());
  }
}
