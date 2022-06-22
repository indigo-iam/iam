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
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
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
@WithMockOAuthUser(user = ScimMeEndpointPatchAddTests.TEST_USERNAME, authorities = {"ROLE_USER"})
public class ScimMeEndpointPatchAddTests extends ScimMeEndpointUtils {

  final static String TEST_USERNAME = "test_103";

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Test
  public void testPatchGivenAndFamilyName() throws Exception {

    ScimUser updates = ScimUser.builder().name(TESTUSER_NEWNAME).build();

    scimUtils.patchMe(add, updates);

    ScimUser userAfter = scimUtils.getMe();

    assertThat(userAfter.getName().getGivenName(), equalTo(updates.getName().getGivenName()));
    assertThat(userAfter.getName().getFamilyName(), equalTo(updates.getName().getFamilyName()));
  }

  @Test
  public void testPatchPicture() throws Exception {

    ScimUser updates = ScimUser.builder().addPhoto(TESTUSER_NEWPHOTO).build();

    scimUtils.patchMe(add, updates);

    ScimUser userAfter = scimUtils.getMe();

    assertThat(userAfter.getPhotos(), hasSize(equalTo(1)));
    assertThat(userAfter.getPhotos().get(0), equalTo(TESTUSER_NEWPHOTO));
  }

  @Test
  public void testPatchEmail() throws Exception {

    ScimUser updates = ScimUser.builder().addEmail(TESTUSER_NEWEMAIL).build();

    scimUtils.patchMe(add, updates);

    ScimUser userAfter = scimUtils.getMe();

    assertThat(userAfter.getEmails().get(0), equalTo(TESTUSER_NEWEMAIL));
  }

  @Test
  public void testPatchMultiple() throws Exception {

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

  @Test
  public void testPatchPasswordNotSupported() throws Exception {

    final String NEW_PASSWORD = "newpassword";

    ScimUser updates = ScimUser.builder().password(NEW_PASSWORD).build();

    scimUtils.patchMe(add, updates, HttpStatus.BAD_REQUEST);
    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser(), nullValue());
  }

  @Test
  public void testPatchAddOidcIdNotSupported() throws Exception {

    ScimOidcId NEW_TESTUSER_OIDCID =
        ScimOidcId.builder().issuer("new_test_issuer").subject("new_user_subject").build();

    ScimUser updates = ScimUser.builder().addOidcId(NEW_TESTUSER_OIDCID).build();

    scimUtils.patchMe(add, updates, HttpStatus.BAD_REQUEST);
    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser(), nullValue());
  }

  @Test
  public void testPatchAddSamlIdNotSupported() throws Exception {

    ScimSamlId TESTUSER_SAMLID = ScimSamlId.builder().idpId("AA").userId("BB").build();

    ScimUser updates = ScimUser.builder().addSamlId(TESTUSER_SAMLID).build();

    scimUtils.patchMe(add, updates, HttpStatus.BAD_REQUEST);
    
    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser(), nullValue());
  }

  @Test
  public void testPatchAddAndRemoveSsHKeyIsSupported() throws Exception {

    ScimSshKey NEW_SSH_KEY =
        ScimSshKey.builder().display("ssh-key").value(SshKeyUtils.sshKeys.get(0).key).build();

    ScimUser updates = ScimUser.builder().addSshKey(NEW_SSH_KEY).build();

    scimUtils.patchMe(add, updates, HttpStatus.NO_CONTENT);

    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));

    scimUtils.patchMe(remove, updates, HttpStatus.NO_CONTENT);

    userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser(), nullValue());
  }

  @Test
  public void testPatchAddX509CertificateNotSupported() throws Exception {

    ScimX509Certificate NEW_X509_CERT = ScimX509Certificate.builder()
      .display("x509-cert")
      .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
      .build();

    ScimUser updates = ScimUser.builder().addX509Certificate(NEW_X509_CERT).build();

    scimUtils.patchMe(add, updates, HttpStatus.BAD_REQUEST);

    ScimUser userAfter = scimUtils.getMe();
    assertThat(userAfter.getIndigoUser(), nullValue());
  }
}
