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
package it.infn.mw.iam.test.scim.me.patch;

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.add;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.remove;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NO_CONTENT;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.SshKeyUtils;
import it.infn.mw.iam.test.X509Utils;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
public class ScimMeEndpointPatchAddTests extends ScimMeEndpointUtils {

  final static String TEST_USERNAME = "test_103";

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  private void patchNameWorks() throws Exception {

    ScimUser updates = ScimUser.builder().name(TESTUSER_NEWNAME).build();
    scimUtils.patchMe(add, updates);
    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getName().getGivenName(), equalTo(updates.getName().getGivenName()));
    assertThat(userAfter.getName().getFamilyName(), equalTo(updates.getName().getFamilyName()));
  }

  private void patchPictureWorks() throws Exception {

    ScimUser updates = ScimUser.builder().addPhoto(TESTUSER_NEWPHOTO).build();
    scimUtils.patchMe(add, updates);
    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getPhotos(), hasSize(equalTo(1)));
    assertThat(userAfter.getPhotos().get(0), equalTo(TESTUSER_NEWPHOTO));
  }

  private void patchEmailWorks() throws Exception {

    ScimUser updates = ScimUser.builder().addEmail(TESTUSER_NEWEMAIL).build();
    scimUtils.patchMe(add, updates);
    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getEmails().get(0), equalTo(TESTUSER_NEWEMAIL));
  }

  private void patchMultipleWorks() throws Exception {

    final ScimUser updates = ScimUser.builder()
      .name(TESTUSER_NEWNAME)
      .addEmail(TESTUSER_NEWEMAIL)
      .addPhoto(TESTUSER_NEWPHOTO)
      .build();
    scimUtils.patchMe(add, updates);
    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getName().getGivenName(), equalTo(updates.getName().getGivenName()));
    assertThat(userAfter.getName().getFamilyName(), equalTo(updates.getName().getFamilyName()));
    assertThat(userAfter.getPhotos(), hasSize(1));
    assertThat(userAfter.getPhotos().get(0), equalTo(TESTUSER_NEWPHOTO));
    assertThat(userAfter.getEmails().get(0), equalTo(TESTUSER_NEWEMAIL));
  }

  private void patchPasswordNotSupported() throws Exception {

    String oldPassword = accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getPassword();

    ScimUser updates = ScimUser.builder().password("newpassword").build();

    scimUtils.patchMe(add, updates, BAD_REQUEST);

    String newPassword = accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getPassword();

    assertThat(oldPassword, equalTo(newPassword));
  }

  private void patchAddOidcIdNotSupported() throws Exception {

    assertThat(accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getOidcIds()
      .isEmpty(), equalTo(true));

    ScimOidcId NEW_OIDCID = ScimOidcId.builder().issuer("ISSUER").subject("SUBJECT").build();

    ScimUser updates = ScimUser.builder().addOidcId(NEW_OIDCID).build();
    scimUtils.patchMe(add, updates, BAD_REQUEST);

    assertThat(accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getOidcIds()
      .isEmpty(), equalTo(true));
  }

  private void patchAddSamlIdNotSupported() throws Exception {

    assertThat(accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getSamlIds()
      .isEmpty(), equalTo(true));

    ScimSamlId NEW_SAMLID = ScimSamlId.builder().idpId("AA").userId("BB").build();

    ScimUser updates = ScimUser.builder().addSamlId(NEW_SAMLID).build();

    scimUtils.patchMe(add, updates, BAD_REQUEST);

    assertThat(accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getSamlIds()
      .isEmpty(), equalTo(true));
  }

  private void patchAddX509CertificateNotSupported() throws Exception {

    assertThat(accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getX509Certificates()
      .isEmpty(), equalTo(true));

    ScimX509Certificate NEW_X509_CERT = ScimX509Certificate.builder()
      .display("x509-cert")
      .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
      .build();

    ScimUser updates = ScimUser.builder().addX509Certificate(NEW_X509_CERT).build();

    scimUtils.patchMe(add, updates, BAD_REQUEST);

    assertThat(accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getX509Certificates()
      .isEmpty(), equalTo(true));
  }

  private void patchAddSshKeyIsSupported() throws Exception {

    assertThat(accountRepository.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new IllegalStateException())
      .getSshKeys()
      .isEmpty(), equalTo(true));

    ScimSshKey NEW_SSH_KEY =
        ScimSshKey.builder().display("ssh-key").value(SshKeyUtils.sshKeys.get(0).key).build();

    ScimUser updates = ScimUser.builder().addSshKey(NEW_SSH_KEY).build();

    scimUtils.patchMe(add, updates, NO_CONTENT);

    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));

    scimUtils.patchMe(remove, updates, NO_CONTENT);

    userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser().getSshKeys().isEmpty(), equalTo(true));
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchGivenAndFamilyName() throws Exception {

    patchNameWorks();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchGivenAndFamilyNameNoToken() throws Exception {

    patchNameWorks();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchPicture() throws Exception {

    patchPictureWorks();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchPictureNoToken() throws Exception {

    patchPictureWorks();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchEmail() throws Exception {


    patchEmailWorks();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchEmailNoEmail() throws Exception {

    patchEmailWorks();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchMultiple() throws Exception {

    patchMultipleWorks();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchMultipleNoToken() throws Exception {

    patchMultipleWorks();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchPasswordNotSupportedWithToken() throws Exception {

    patchPasswordNotSupported();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchPasswordNotSupportedAsUser() throws Exception {

    patchPasswordNotSupported();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchAddOidcIdNotSupported() throws Exception {

    patchAddOidcIdNotSupported();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchAddOidcIdNotSupportedNoToken() throws Exception {

    patchAddOidcIdNotSupported();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchAddSamlIdNotSupported() throws Exception {

    patchAddSamlIdNotSupported();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchAddSamlIdNotSupportedNoToken() throws Exception {

    patchAddSamlIdNotSupported();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchAddAndRemoveSsHKeyIsSupported() throws Exception {

    patchAddSshKeyIsSupported();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})
  public void testPatchAddAndRemoveSsHKeyIsSupportedNoToken() throws Exception {

    patchAddSshKeyIsSupported();
  }

  @Test
  @WithMockOAuthUser(user = TEST_USERNAME, scopes = {"scim:read", "scim:write"})
  public void testPatchAddX509CertificateNotSupported() throws Exception {

    patchAddX509CertificateNotSupported();
  }

  @Test
  @WithMockUser(username = TEST_USERNAME, roles = {"USER"})

  public void testPatchAddX509CertificateNotSupportedNoToken() throws Exception {

    patchAddX509CertificateNotSupported();

  }
}
