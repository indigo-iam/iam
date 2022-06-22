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
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
public class ScimUserProvisioningPatchTests extends ScimUserTestSupport {

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private PasswordEncoder encoder;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  private final String PICTURE_URL = "http://iosicongallery.com/img/512/angry-birds-2-2016.png";

  private ScimUser lennon;
  private ScimUser lincoln;

  @Before
  public void setup() throws Exception {

    lennon = createScimUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = createScimUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() throws Exception {

    deleteScimUser(lennon);
    deleteScimUser(lincoln);
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testPatchUserInfo() throws Exception {

    ScimName name = ScimName.builder().givenName("John jr.").familyName("Lennon II").build();

    /*
     * Update: - email - username - active - name - address
     */
    ScimUser lennon_updates = ScimUser.builder("john_lennon_jr")
      .buildEmail("john_lennon_jr@email.com")
      .active(!lennon.getActive())
      .name(name)
      .build();

    scimUtils.patchUser(lennon.getId(), add, lennon_updates);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getId(), equalTo(lennon.getId()));
    assertThat(updatedUser.getUserName(), equalTo(lennon_updates.getUserName()));
    assertThat(updatedUser.getDisplayName(), equalTo(lennon_updates.getUserName()));
    assertThat(updatedUser.getName().getGivenName(),
        equalTo(lennon_updates.getName().getGivenName()));
    assertThat(updatedUser.getName().getMiddleName(),
        equalTo(lennon_updates.getName().getMiddleName()));
    assertThat(updatedUser.getName().getFamilyName(),
        equalTo(lennon_updates.getName().getFamilyName()));
    assertThat(updatedUser.getActive(), equalTo(lennon_updates.getActive()));
    assertThat(updatedUser.getEmails(), hasSize(equalTo(1)));
    assertThat(updatedUser.getEmails().get(0).getValue(),
        equalTo(lennon_updates.getEmails().get(0).getValue()));

  }

  @Test
  public void testAddReassignAndRemoveOidcId() throws Exception {

    ScimIndigoUser indigoUser = ScimIndigoUser.builder().addOidcid(OIDCID_TEST).build();

    ScimUser updateOidcId = ScimUser.builder().indigoUserInfo(indigoUser).build();

    scimUtils.patchUser(lennon.getId(), add, updateOidcId);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo(OIDCID_TEST.getIssuer()));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getSubject(),
        equalTo(OIDCID_TEST.getSubject()));

    /* lincoln tryes to add the oidc account: */
    scimUtils.patchUser(lincoln.getId(), add, updateOidcId, HttpStatus.CONFLICT);

    /* Remove oidc account */
    scimUtils.patchUser(lennon.getId(), remove, updateOidcId);

    updatedUser = scimUtils.getUser(lennon.getId());
    assertNull(updatedUser.getIndigoUser());
  }

  @Test
  public void testAddReassignAndRemoveSamlId() throws Exception {

    ScimUser updateSamlId = ScimUser.builder()
      .indigoUserInfo(ScimIndigoUser.builder().addSamlId(SAMLID_TEST).build())
      .build();

    scimUtils.patchUser(lennon.getId(), add, updateSamlId);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getIdpId(),
        equalTo(SAMLID_TEST.getIdpId()));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getUserId(),
        equalTo(SAMLID_TEST.getUserId()));

    /* lincoln tryes to add the oidc account: */
    scimUtils.patchUser(lincoln.getId(), add, updateSamlId, HttpStatus.CONFLICT);

    /* Remove oidc account */
    scimUtils.patchUser(lennon.getId(), remove, updateSamlId);

    updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getId(), equalTo(lennon.getId()));
    assertNull(updatedUser.getIndigoUser());
  }

  @Test
  public void testRemoveNotExistingOidcId() throws Exception {

    ScimUser updates = ScimUser.builder()
      .indigoUserInfo(ScimIndigoUser.builder().addOidcid(OIDCID_TEST).build())
      .build();

    scimUtils.patchUser(lennon.getId(), remove, updates);
  }

  @Test
  public void testAddInvalidBase64X509Certificate() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display("Personal Certificate")
      .pemEncodedCertificate("This is not a certificate")
      .primary(true)
      .build();

    ScimUser lennon_update = ScimUser.builder().addX509Certificate(cert).build();

    scimUtils.patchUser(lennon.getId(), add, lennon_update, HttpStatus.BAD_REQUEST);
  }

  @Test
  public void testAddInvalidX509Certificate() throws Exception {

    String certificate = Base64.getEncoder().encodeToString("this is not a certificate".getBytes());

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display("Personal Certificate")
      .pemEncodedCertificate(certificate)
      .primary(true)
      .build();

    ScimUser lennon_update = ScimUser.builder().addX509Certificate(cert).build();

    scimUtils.patchUser(lennon.getId(), add, lennon_update, HttpStatus.BAD_REQUEST);
  }

  @Test
  public void testAddAndRemoveX509Certificate() throws Exception {

    ScimUser lennon_update = ScimUser.builder().addX509Certificate(X509CERT_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, lennon_update);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    List<ScimX509Certificate> updatedUserCertList = updatedUser.getIndigoUser().getCertificates();

    assertThat(updatedUserCertList, hasSize(equalTo(1)));
    assertThat(updatedUserCertList.get(0).getPemEncodedCertificate(),
        equalTo(X509CERT_TEST.getPemEncodedCertificate()));
    assertThat(updatedUserCertList.get(0).getDisplay(), equalTo(X509CERT_TEST.getDisplay()));

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display(null)
      .pemEncodedCertificate(X509CERT_TEST.getPemEncodedCertificate())
      .build();

    ScimUser lennon_remove = ScimUser.builder().addX509Certificate(cert).build();

    scimUtils.patchUser(lennon.getId(), remove, lennon_remove);

    updatedUser = scimUtils.getUser(lennon.getId());
    assertNull(updatedUser.getIndigoUser());
  }

  @Test
  public void testPatchUserPassword() throws Exception {

    final String NEW_PASSWORD = "new_password";

    ScimUser patchedPasswordUser = ScimUser.builder().password(NEW_PASSWORD).build();

    scimUtils.patchUser(lennon.getId(), add, patchedPasswordUser);

    Optional<IamAccount> lennonAccount = accountRepo.findByUuid(lennon.getId());
    if (!lennonAccount.isPresent()) {
      Assert.fail("Account not found");
    }

    assertThat(lennonAccount.get().getPassword(), notNullValue());
    assertThat(encoder.matches(NEW_PASSWORD, lennonAccount.get().getPassword()), equalTo(true));
  }

  @Test
  public void testAddReassignAndRemoveSshKey() throws Exception {

    ScimUser updateSshKey = ScimUser.builder().addSshKey(SSHKEY_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updateSshKey);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SSHKEY_TEST.getValue()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getDisplay(),
        equalTo(SSHKEY_TEST.getDisplay()));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SSHKEY_TEST_FINGERPRINT));
    assertThat(updatedUser.getIndigoUser().getSshKeys().get(0).isPrimary(), equalTo(true));

    /* lincoln tryes to add the lennon ssh key: */
    scimUtils.patchUser(lincoln.getId(), add, updateSshKey, HttpStatus.CONFLICT);

    scimUtils.patchUser(lennon.getId(), remove, updateSshKey);
  }


  @Test
  public void testRemoveSshKeyWithValue() throws Exception {

    ScimUser updateSshKey = ScimUser.builder().addSshKey(SSHKEY_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updateSshKey);

    updateSshKey = ScimUser.builder()
      .indigoUserInfo(ScimIndigoUser.builder()
        .addSshKey(ScimSshKey.builder().value(SSHKEY_TEST.getValue()).build())
        .build())
      .build();

    scimUtils.patchUser(lennon.getId(), remove, updateSshKey);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertNull(updatedUser.getIndigoUser());
  }

  @Test
  public void testAddOidcIdDuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder().addOidcId(OIDCID_TEST).addOidcId(OIDCID_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updates);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getId(), equalTo(lennon.getId()));
    assertThat(updatedUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo(OIDCID_TEST.getIssuer()));
    assertThat(updatedUser.getIndigoUser().getOidcIds().get(0).getSubject(),
        equalTo(OIDCID_TEST.getSubject()));
  }

  @Test
  public void testAddSshKeyDuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder().addSshKey(SSHKEY_TEST).addSshKey(SSHKEY_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updates);

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
  public void testAddSamlIdDuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder().addSamlId(SAMLID_TEST).addSamlId(SAMLID_TEST).build();

    scimUtils.patchUser(lennon.getId(), add, updates);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getIdpId(),
        equalTo(SAMLID_TEST.getIdpId()));
    assertThat(updatedUser.getIndigoUser().getSamlIds().get(0).getUserId(),
        equalTo(SAMLID_TEST.getUserId()));
  }

  @Test
  public void testAddX509DuplicateInASingleRequest() throws Exception {

    ScimUser updates = ScimUser.builder()
      .addX509Certificate(X509CERT_TEST)
      .addX509Certificate(X509CERT_TEST)
      .build();

    scimUtils.patchUser(lennon.getId(), add, updates);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    List<ScimX509Certificate> updatedUserCertList = updatedUser.getIndigoUser().getCertificates();

    assertThat(updatedUserCertList, hasSize(equalTo(1)));
    assertThat(updatedUserCertList.get(0).getPemEncodedCertificate(),
        equalTo(X509CERT_TEST.getPemEncodedCertificate()));
    assertThat(updatedUserCertList.get(0).getDisplay(), equalTo(X509CERT_TEST.getDisplay()));
  }

  @Test
  public void testPatchAddOidIdAndSshKeyAndSamlId() throws Exception {

    ScimUser updates = ScimUser.builder()
      .addX509Certificate(X509CERT_TEST)
      .addOidcId(OIDCID_TEST)
      .addSshKey(SSHKEY_TEST)
      .addSamlId(SAMLID_TEST)
      .build();

    scimUtils.patchUser(lennon.getId(), add, updates);

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
  public void testEmailIsNotAlreadyLinkedOnPatch() throws Exception {

    String alreadyBoundEmail = lincoln.getEmails().get(0).getValue();
    ScimUser lennonUpdates = ScimUser.builder().buildEmail(alreadyBoundEmail).build();

    scimUtils.patchUser(lennon.getId(), add, lennonUpdates, HttpStatus.CONFLICT)
      .andExpect(jsonPath("$.detail",
          containsString("Email " + alreadyBoundEmail + " already bound to another user")));
  }

  @Test
  public void testAddPicture() throws Exception {

    ScimUser updates = ScimUser.builder().buildPhoto(PICTURE_URL).build();

    scimUtils.patchUser(lennon.getId(), add, updates);

    ScimUser updatedUser = scimUtils.getUser(lennon.getId());
    assertThat(updatedUser.getPhotos(), hasSize(equalTo(1)));
    assertThat(updatedUser.getPhotos().get(0).getValue(), equalTo(PICTURE_URL));
  }
}
