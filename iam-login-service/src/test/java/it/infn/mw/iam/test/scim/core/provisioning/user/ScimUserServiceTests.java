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
package it.infn.mw.iam.test.scim.core.provisioning.user;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.SshKeyUtils;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;

@RunWith(SpringRunner.class)
@IamNoMvcTest
public class ScimUserServiceTests {

  @Autowired
  private ScimUserProvisioning userService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private PasswordEncoder passwordEncoder;

  final String TESTUSER_USERNAME = "testProvisioningUser";
  final String TESTUSER_PASSWORD = "password";
  final ScimName TESTUSER_NAME = ScimName.builder().givenName("John").familyName("Lennon").build();
  final ScimEmail TESTUSER_EMAIL = ScimEmail.builder().email("john.lennon@liverpool.uk").build();
  final ScimPhoto TESTUSER_PHOTO = ScimPhoto.builder().value("http://site.org/user.png").build();
  final ScimOidcId TESTUSER_OIDCID =
      ScimOidcId.builder().issuer("urn:oidc:test:issuer").subject("1234").build();
  final ScimSamlId TESTUSER_SAMLID = ScimSamlId.builder().idpId("idpID").userId("userId").build();
  final ScimSshKey TESTUSER_SSHKEY = ScimSshKey.builder()
    .primary(true)
    .display("Personal Key")
    .value(SshKeyUtils.sshKeys.get(0).key)
    .build();

  @Test
  public void createUserTest() {

    ScimUser scimUser = ScimUser.builder()
      .active(true)
      .userName(TESTUSER_USERNAME)
      .password(TESTUSER_PASSWORD)
      .name(TESTUSER_NAME)
      .addEmail(TESTUSER_EMAIL)
      .addPhoto(TESTUSER_PHOTO)
      .addOidcId(TESTUSER_OIDCID)
      .addSamlId(TESTUSER_SAMLID)
      .addSshKey(TESTUSER_SSHKEY)
      .build();

    userService.create(scimUser);

    IamAccount iamAccount = accountRepo.findByUsername(scimUser.getUserName())
      .orElseThrow(() -> new AssertionError("Expected user not found by policyRepo"));

    assertNotNull(iamAccount);

    assertThat(iamAccount.isActive(), equalTo(true));

    assertThat(iamAccount.getUsername(), equalTo(TESTUSER_USERNAME));

    assertTrue(passwordEncoder.matches(TESTUSER_PASSWORD, iamAccount.getPassword()));

    assertThat(iamAccount.getUserInfo().getGivenName(), equalTo(TESTUSER_NAME.getGivenName()));
    assertThat(iamAccount.getUserInfo().getMiddleName(), equalTo(TESTUSER_NAME.getMiddleName()));
    assertThat(iamAccount.getUserInfo().getFamilyName(), equalTo(TESTUSER_NAME.getFamilyName()));

    assertThat(iamAccount.getUserInfo().getPicture(), equalTo(TESTUSER_PHOTO.getValue()));

    assertThat(iamAccount.getUserInfo().getEmail(), equalTo(TESTUSER_EMAIL.getValue()));

    
    IamOidcId oidcId = iamAccount.getOidcIds().iterator().next();
    assertThat(oidcId.getIssuer(), equalTo(TESTUSER_OIDCID.getIssuer()));
    assertThat(oidcId.getSubject(), equalTo(TESTUSER_OIDCID.getSubject()));

    IamSamlId samlId = iamAccount.getSamlIds().iterator().next();
    
    assertThat(samlId.getIdpId(), equalTo(TESTUSER_SAMLID.getIdpId()));
    assertThat(samlId.getUserId(), equalTo(TESTUSER_SAMLID.getUserId()));

    IamSshKey sshKey = iamAccount.getSshKeys().iterator().next();
    
    assertThat(sshKey.getLabel(), equalTo(TESTUSER_SSHKEY.getDisplay()));
    assertThat(sshKey.getFingerprint(),
        equalTo(SshKeyUtils.sshKeys.get(0).fingerprintSHA256));
    assertThat(sshKey.getValue(), equalTo(TESTUSER_SSHKEY.getValue()));
    assertThat(sshKey.isPrimary(), equalTo(TESTUSER_SSHKEY.isPrimary()));

    userService.delete(iamAccount.getUuid());
  }
}
