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

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.test.OidcIdUtils;
import it.infn.mw.iam.test.SamlIdUtils;
import it.infn.mw.iam.test.SshKeyUtils;
import it.infn.mw.iam.test.X509Utils;
import it.infn.mw.iam.test.scim.ScimUtils;

public class ScimUserTestSupport {

  @Autowired
  private ScimUserProvisioning provider;

  protected ScimOidcId OIDCID_TEST =
      ScimOidcId.builder().issuer("test_issuer").subject("test_subject").build();

  protected ScimSamlId SAMLID_TEST =
      ScimSamlId.builder().idpId("test_idp").userId("test_user").build();

  protected ScimX509Certificate X509CERT_TEST = ScimX509Certificate.builder()
    .display("Personal Certificate")
    .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
    .primary(true)
    .build();

  protected String SSHKEY_TEST_FINGERPRINT = SshKeyUtils.sshKeys.get(0).fingerprintSHA256;

  protected ScimSshKey SSHKEY_TEST = ScimSshKey.builder()
    .display("Personal")
    .value(SshKeyUtils.sshKeys.get(0).key)
    .primary(true)
    .build();

  protected List<String> PICTURES =
      Lists.newArrayList("http://iosicongallery.com/img/512/angry-birds-2-2016.png",
          "https://fallofthewall25.com/img/default-user.jpg");

  protected ScimUser createLincolnTestUser() {
    ScimUser lincoln = ScimUser.builder("abraham_lincoln")
      .buildEmail("lincoln@email.test")
      .buildName("Abraham", "Lincoln")
      .addOidcId(ScimOidcId.builder()
        .issuer(OidcIdUtils.oidcIds.get(1).issuer)
        .subject(OidcIdUtils.oidcIds.get(1).subject)
        .build())
      .addSshKey(ScimSshKey.builder()
        .value(SshKeyUtils.sshKeys.get(1).key)
        .fingerprint(SshKeyUtils.sshKeys.get(1).fingerprintSHA256)
        .primary(true)
        .build())
      .addSamlId(ScimSamlId.builder()
        .idpId(SamlIdUtils.samlIds.get(1).idpId)
        .userId(SamlIdUtils.samlIds.get(1).userId)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(X509Utils.x509Certs.get(1).display)
        .pemEncodedCertificate(X509Utils.x509Certs.get(1).certificate)
        .primary(true)
        .build())
      .build();

    return provider.create(lincoln);
  }
  protected ScimUser createLennonTestUser() {
    ScimUser lennon = ScimUser.builder("john_lennon")
      .buildEmail("lennon@email.test")
      .buildName("John", "Lennon")
      .buildPhoto(PICTURES.get(0))
      .addOidcId(ScimOidcId.builder()
        .issuer(OidcIdUtils.oidcIds.get(0).issuer)
        .subject(OidcIdUtils.oidcIds.get(0).subject)
        .build())
      .addSshKey(ScimSshKey.builder()
        .value(SshKeyUtils.sshKeys.get(0).key)
        .fingerprint(SshKeyUtils.sshKeys.get(0).fingerprintSHA256)
        .primary(true)
        .build())
      .addSamlId(ScimSamlId.builder()
        .idpId(SamlIdUtils.samlIds.get(0).idpId)
        .userId(SamlIdUtils.samlIds.get(0).userId)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(X509Utils.x509Certs.get(0).display)
        .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
        .primary(true)
        .build())
      .build();

    return provider.create(lennon);
  }

  protected List<ScimUser> createTestUsers() {
    List<ScimUser> testUsers = new ArrayList<ScimUser>();

    ScimUser lennon = ScimUser.builder("john_lennon")
      .buildEmail("lennon@email.test")
      .buildName("John", "Lennon")
      .buildPhoto(PICTURES.get(0))
      .addOidcId(ScimOidcId.builder()
        .issuer(OidcIdUtils.oidcIds.get(0).issuer)
        .subject(OidcIdUtils.oidcIds.get(0).subject)
        .build())
      .addSshKey(ScimSshKey.builder()
        .value(SshKeyUtils.sshKeys.get(0).key)
        .fingerprint(SshKeyUtils.sshKeys.get(0).fingerprintSHA256)
        .primary(true)
        .build())
      .addSamlId(ScimSamlId.builder()
        .idpId(SamlIdUtils.samlIds.get(0).idpId)
        .userId(SamlIdUtils.samlIds.get(0).userId)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(X509Utils.x509Certs.get(0).display)
        .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
        .primary(true)
        .build())
      .build();

    testUsers.add(provider.create(lennon));

    ScimUser lincoln = ScimUser.builder("abraham_lincoln")
      .buildEmail("lincoln@email.test")
      .buildName("Abraham", "Lincoln")
      .addOidcId(ScimOidcId.builder()
        .issuer(OidcIdUtils.oidcIds.get(1).issuer)
        .subject(OidcIdUtils.oidcIds.get(1).subject)
        .build())
      .addSshKey(ScimSshKey.builder()
        .value(SshKeyUtils.sshKeys.get(1).key)
        .fingerprint(SshKeyUtils.sshKeys.get(1).fingerprintSHA256)
        .primary(true)
        .build())
      .addSamlId(ScimSamlId.builder()
        .idpId(SamlIdUtils.samlIds.get(1).idpId)
        .userId(SamlIdUtils.samlIds.get(1).userId)
        .build())
      .addX509Certificate(ScimX509Certificate.builder()
        .display(X509Utils.x509Certs.get(1).display)
        .pemEncodedCertificate(X509Utils.x509Certs.get(1).certificate)
        .primary(true)
        .build())
      .build();

    testUsers.add(provider.create(lincoln));

    return testUsers;
  }

  protected ScimUser createScimUser(String username, String email, String givenName,
      String familyName) {
    ScimUser user = ScimUtils.buildUser(username, email, givenName, familyName);
    return provider.create(user);
  }

  protected void deleteScimUser(ScimUser user) {
    provider.delete(user.getId());
  }

  protected String getRandomUUid() {
    return UUID.randomUUID().toString();
  }
}
