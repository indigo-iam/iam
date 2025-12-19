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
package it.infn.mw.iam.test.scim.user;

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.add;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.remove;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.replace;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimEmail.ScimEmailType;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {"spring.main.allow-bean-definition-overriding=true",})
@Transactional
class ScimUserProvisioningPatchTests extends ScimUserTestSupport {

  static final String PICTURE_URL =
      "https://cdn.jim-nielsen.com/ios/512/angry-birds-2-2024-09-01.png?rf=1024";

  @Autowired
  ScimRestUtilsMvc scimUtils;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  ScimUser lennon;
  ScimUser lincoln;

  @BeforeEach
  void setup() {

    lennon = createScimUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = createScimUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {

    /*
     * @Transactional annotation ensures the created test users won't exist after the test
     */
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  void testPatchUserInfo() throws Exception {

    ScimName name = ScimName.builder().givenName("John jr.").familyName("Lennon II").build();

    /*
     * Update: - email - username - active - name - address
     */
    ScimUser lennon_updates = ScimUser.builder("john_lennon_jr")
      .buildEmail("john_lennon_jr@email.com")
      .active(!lennon.getActive())
      .name(name)
      .build();

    scimUtils.patchUser(lennon.getId(), add, lennon_updates).andExpect(status().isNoContent());

    ScimUser u = scimUtils.getUser(lennon.getId());
    assertThat(u.getId(), equalTo(lennon.getId()));
    assertThat(u.getUserName(), equalTo(lennon_updates.getUserName()));
    assertThat(u.getDisplayName(), equalTo(lennon_updates.getUserName()));
    assertThat(u.getName().getGivenName(), equalTo(lennon_updates.getName().getGivenName()));
    assertThat(u.getName().getMiddleName(), equalTo(lennon_updates.getName().getMiddleName()));
    assertThat(u.getName().getFamilyName(), equalTo(lennon_updates.getName().getFamilyName()));
    assertThat(u.getActive(), equalTo(lennon_updates.getActive()));
    assertThat(u.getEmails(), hasSize(equalTo(1)));
    assertThat(u.getEmails().get(0).getValue(),
        equalTo(lennon_updates.getEmails().get(0).getValue()));

  }

  @Test
  void testAddReassignAndRemoveOidcId() throws Exception {

    ScimUser updateOidcId = ScimUser.builder().addOidcId(OIDCID_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updateOidcId).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo(OIDCID_TEST.getIssuer()));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getSubject(),
        equalTo(OIDCID_TEST.getSubject()));

    /* lincoln tryes to add the oidc account: */
    scimUtils.patchUser(lincoln.getId(), add, updateOidcId).andExpect(status().isConflict());

    /* Remove oidc account */
    scimUtils.patchUser(lennon.getId(), remove, updateOidcId).andExpect(status().isNoContent());

    updatedUser = scimUtils.getUser(lennon.getId());
    assertTrue(updatedUser.getIndigoUser().getOidcIds().isEmpty());
  }

  @Test
  void testAddReassignAndRemoveSamlId() throws Exception {

    ScimUser updateSamlId = ScimUser.builder().addSamlId(SAMLID_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updateSamlId).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getIdpId(),
        equalTo(SAMLID_TEST.getIdpId()));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getUserId(),
        equalTo(SAMLID_TEST.getUserId()));

    /* lincoln tryes to add the oidc account: */
    scimUtils.patchUser(lincoln.getId(), add, updateSamlId).andExpect(status().isConflict());

    /* Remove oidc account */
    scimUtils.patchUser(lennon.getId(), remove, updateSamlId).andExpect(status().isNoContent());

    updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getId(), equalTo(lennon.getId()));
    assertTrue(updatedUser.getIndigoUser().getSamlIds().isEmpty());
  }

  @Test
  void testRemoveNotExistingOidcId() throws Exception {

    ScimUser updates = ScimUser.builder().addOidcId(OIDCID_TEST).build();

    scimUtils.patchUser(lennon.getId(), remove, updates).andExpect(status().isNoContent());
  }

  @Test
  void testAddInvalidBase64X509Certificate() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display("Personal Certificate")
      .pemEncodedCertificate("This is not a certificate")
      .primary(true)
      .build();

    ScimUser lennon_update = ScimUser.builder().addX509Certificate(cert).build();

    scimUtils.patchUser(lennon.getId(), add, lennon_update).andExpect(status().isBadRequest());
  }

  @Test
  void testAddInvalidX509Certificate() throws Exception {

    String certificate = Base64.getEncoder().encodeToString("this is not a certificate".getBytes());

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display("Personal Certificate")
      .pemEncodedCertificate(certificate)
      .primary(true)
      .build();

    ScimUser lennon_update = ScimUser.builder().addX509Certificate(cert).build();

    scimUtils.patchUser(lennon.getId(), add, lennon_update).andExpect(status().isBadRequest());
  }

  @Test
  void testAddAndRemoveX509Certificate() throws Exception {

    ScimUser lennon_update = ScimUser.builder().addX509Certificate(X509CERT_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, lennon_update).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    List<ScimX509Certificate> updatedUserCertList = updatedUser.getIndigoUser().getCertificates();

    assertThat(updatedUserCertList, hasSize(equalTo(1)));
    assertThat(updatedUserCertList.get(0).getPemEncodedCertificate(),
        equalTo(X509CERT_TEST.getPemEncodedCertificate()));
    assertThat(updatedUserCertList.get(0).getDisplay(), equalTo(X509CERT_TEST.getDisplay()));

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(null)
      .pemEncodedCertificate(X509CERT_TEST.getPemEncodedCertificate())
      .subjectDn(X509CERT_TEST.getSubjectDn())
      .issuerDn(X509CERT_TEST.getIssuerDn())
      .build();

    ScimUser lennon_remove = ScimUser.builder().addX509Certificate(cert).build();

    scimUtils.patchUser(lennon.getId(), remove, lennon_remove);

    updatedUser = scimUtils.getUser(lennon.getId());
    assertTrue(updatedUser.getIndigoUser().getCertificates().isEmpty());
  }

  @Test
  void testAddAndRemoveMultipleX509Certificate() throws Exception {

    ScimUser lennonUpdate = ScimUser.builder()
      .addX509Certificate(X509CERT_TEST)
      .addX509Certificate(X509CERT_TEST2)
      .build();

    scimUtils.patchUser(lennon.getId(), add, lennonUpdate).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    List<ScimX509Certificate> updatedUserCertList = updatedUser.getIndigoUser().getCertificates();

    assertThat(updatedUserCertList, hasSize(equalTo(2)));

    assertThat(updatedUserCertList.stream().map(u -> u.getPemEncodedCertificate()).toList(),
        containsInAnyOrder(X509CERT_TEST.getPemEncodedCertificate(),
            X509CERT_TEST2.getPemEncodedCertificate()));

    assertThat(updatedUserCertList.stream().map(u -> u.getDisplay()).toList(),
        containsInAnyOrder(X509CERT_TEST.getDisplay(), X509CERT_TEST2.getDisplay()));

    ScimUser lennonRemove = ScimUser.builder().addX509Certificate(X509CERT_TEST).build();

    scimUtils.patchUser(lennon.getId(), remove, lennonRemove);

    updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getCertificates(), hasSize(1));
    assertThat(updatedUser.getIndigoUser().getCertificates().get(0).getPemEncodedCertificate(),
        equalTo(X509CERT_TEST2.getPemEncodedCertificate()));

    assertThat(updatedUser.getIndigoUser().getCertificates().get(0).getDisplay(),
        equalTo(X509CERT_TEST2.getDisplay()));

    ScimUser lennonRemoveSecond = ScimUser.builder().addX509Certificate(X509CERT_TEST2).build();

    scimUtils.patchUser(lennon.getId(), remove, lennonRemoveSecond);

    updatedUser = scimUtils.getUser(lennon.getId());

    assertTrue(updatedUser.getIndigoUser().getCertificates().isEmpty());
  }

  @Test
  void testPatchUserPassword() throws Exception {

    final String NEW_PASSWORD = "new_password";

    ScimUser patchedPasswordUser = ScimUser.builder().password(NEW_PASSWORD).build();

    scimUtils.patchUser(lennon.getId(), add, patchedPasswordUser).andExpect(status().isNoContent());

    Optional<IamAccount> lennonAccount = accountRepo.findByUuid(lennon.getId());
    if (!lennonAccount.isPresent()) {
      fail("Account not found");
    }

    assertThat(lennonAccount.get().getPassword(), notNullValue());
    assertThat(encoder.matches(NEW_PASSWORD, lennonAccount.get().getPassword()), equalTo(true));
  }

  @Test
  void testAddReassignAndRemoveSshKey() throws Exception {

    ScimUser updateSshKey = ScimUser.builder().addSshKey(SSHKEY_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updateSshKey).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SSHKEY_TEST.getValue()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getDisplay(),
        equalTo(SSHKEY_TEST.getDisplay()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SSHKEY_TEST_FINGERPRINT));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).isPrimary(), equalTo(true));

    /* Lincoln tries to add Lennon's SSH key: */
    scimUtils.patchUser(lincoln.getId(), add, updateSshKey).andExpect(status().isConflict());

    scimUtils.patchUser(lennon.getId(), remove, updateSshKey).andExpect(status().isNoContent());
  }

  @Test
  void testRemoveSshKeyWithValue() throws Exception {

    ScimUser updateSshKey = ScimUser.builder().addSshKey(SSHKEY_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updateSshKey).andExpect(status().isNoContent());

    updateSshKey = ScimUser.builder()
      .addSshKey(ScimSshKey.builder().value(SSHKEY_TEST.getValue()).build())
      .build();

    scimUtils.patchUser(lennon.getId(), remove, updateSshKey).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertTrue(updatedUser.getIndigoUser().getSshKeys().isEmpty());
  }

  @Test
  void testAddOidcIdDuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder().addOidcId(OIDCID_TEST).addOidcId(OIDCID_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updates).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getId(), equalTo(lennon.getId()));
    assertThat(updatedUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo(OIDCID_TEST.getIssuer()));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getSubject(),
        equalTo(OIDCID_TEST.getSubject()));
  }

  @Test
  void testAddSshKeyDuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder().addSshKey(SSHKEY_TEST).addSshKey(SSHKEY_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updates).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SSHKEY_TEST.getValue()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getDisplay(),
        equalTo(SSHKEY_TEST.getDisplay()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SSHKEY_TEST_FINGERPRINT));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).isPrimary(), equalTo(true));
  }

  @Test
  void testAddSamlIdDuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder().addSamlId(SAMLID_TEST).addSamlId(SAMLID_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updates).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getIdpId(),
        equalTo(SAMLID_TEST.getIdpId()));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getUserId(),
        equalTo(SAMLID_TEST.getUserId()));
  }

  @Test
  void testAddX509DuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder()
      .addX509Certificate(X509CERT_TEST)
      .addX509Certificate(X509CERT_TEST)
      .build();

    scimUtils.patchUser(lennon.getId(), add, updates).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    List<ScimX509Certificate> updatedUserCertList = updatedUser.getIndigoUser().getCertificates();

    assertThat(updatedUserCertList, hasSize(equalTo(1)));
    assertThat(updatedUserCertList.get(0).getPemEncodedCertificate(),
        equalTo(X509CERT_TEST.getPemEncodedCertificate()));
    assertThat(updatedUserCertList.get(0).getDisplay(), equalTo(X509CERT_TEST.getDisplay()));
  }

  @Test
  void testPatchAddOidIdAndSshKeyAndSamlId() throws Exception {

    ScimUser updates = ScimUser.builder()
      .addX509Certificate(X509CERT_TEST)
      .addOidcId(OIDCID_TEST)
      .addSshKey(SSHKEY_TEST)
      .addSamlId(SAMLID_TEST)
      .build();

    scimUtils.patchUser(lennon.getId(), add, updates).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    List<ScimX509Certificate> updatedUserCertList = updatedUser.getIndigoUser().getCertificates();

    assertThat(updatedUserCertList, hasSize(equalTo(1)));
    assertThat(updatedUserCertList.get(0).getPemEncodedCertificate(),
        equalTo(X509CERT_TEST.getPemEncodedCertificate()));
    assertThat(updatedUserCertList.get(0).getDisplay(), equalTo(X509CERT_TEST.getDisplay()));
    assertThat(updatedUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getIdpId(),
        equalTo(SAMLID_TEST.getIdpId()));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getUserId(),
        equalTo(SAMLID_TEST.getUserId()));
    assertThat(updatedUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SSHKEY_TEST.getValue()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getDisplay(),
        equalTo(SSHKEY_TEST.getDisplay()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SSHKEY_TEST_FINGERPRINT));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).isPrimary(), equalTo(true));
    assertThat(updatedUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo(OIDCID_TEST.getIssuer()));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getSubject(),
        equalTo(OIDCID_TEST.getSubject()));
  }

  @Test
  void testEmailIsNotAlreadyLinkedOnPatch() throws Exception {

    String alreadyBoundEmail = lincoln.getEmails().get(0).getValue();
    ScimUser lennonUpdates = ScimUser.builder().buildEmail(alreadyBoundEmail).build();

    scimUtils.patchUser(lennon.getId(), add, lennonUpdates)
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail",
          containsString("Email " + alreadyBoundEmail + " already bound to another user")));
  }

  @Test
  void testAddPicture() throws Exception {

    ScimUser updates = ScimUser.builder().buildPhoto(PICTURE_URL).build();

    scimUtils.patchUser(lennon.getId(), add, updates).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getPhotos(), hasSize(equalTo(1)));
    assertThat(updatedUser.getPhotos().get(0).getValue(), equalTo(PICTURE_URL));
  }

  @Test
  @WithMockUser(username = "john_lennon", roles = {"USER"})
  void testUserCanNotChangeAccountType() throws Exception {
    ScimUser updates = ScimUser.builder().serviceAccount(true).build();

    scimUtils.patchUser(lennon.getId(), replace, updates).andExpect(status().isBadRequest());
  }

  @Test
  @WithMockUser(username = "john_lennon", roles = {"USER"})
  void testUserCanChangeEmail() throws Exception {
    ScimUser updates = ScimUser.builder()
      .addEmail(ScimEmail.builder()
        .email("TestUser@example.com")
        .type(ScimEmailType.home)
        .primary(false)
        .build())
      .build();

    scimUtils.patchUser(lennon.getId(), replace, updates).andExpect(status().isNoContent());

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    ScimEmail updatedEmail = updatedUser.getEmails()
      .stream()
      .filter(e -> "TestUser@example.com".equals(e.getValue()))
      .findFirst()
      .orElseThrow(() -> new AssertionError("Email not found"));
    // Values of Type and Primary are unchanged
    assertThat(updatedEmail.getPrimary(), is(true));
    assertThat(updatedEmail.getType(), is(ScimEmailType.work));
  }
}
