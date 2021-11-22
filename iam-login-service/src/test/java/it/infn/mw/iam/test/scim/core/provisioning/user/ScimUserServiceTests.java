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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.account.group_manager.AccountGroupManagerService;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimLabel;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.SshKeyUtils;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;

@RunWith(SpringJUnit4ClassRunner.class)
@IamNoMvcTest
public class ScimUserServiceTests {

  @Autowired
  private ScimUserProvisioning userService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  private AccountGroupManagerService groupManager;

  @Autowired
  private ScimResourceLocationProvider resourceLocationProvider;

  final String TESTUSER_ATTRIBUTE_NAME = "attribute-name";
  final String TESTUSER_ATTRIBUTE_VALUE = "attribute-value";
  final String TESTUSER_LABEL_NAME = "label-name";
  final String TESTUSER_LABEL_VALUE = "label-value";
  final String PRODUCTION_GROUP_UUID = "c617d586-54e6-411d-8e38-64967798fa8a";
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
  final ScimAttribute TESTUSER_ATTRIBUTE = ScimAttribute.builder()
    .withName(TESTUSER_ATTRIBUTE_NAME)
    .withVaule(TESTUSER_ATTRIBUTE_VALUE)
    .build();
  final ScimLabel TESTUSER_LABEL =
      ScimLabel.builder().withName(TESTUSER_LABEL_NAME).withVaule(TESTUSER_LABEL_VALUE).build();

  private ScimGroupRef TESTUSER_GROUP_REF;

  @Before
  public void setup() {
    TESTUSER_GROUP_REF = ScimGroupRef.builder()
      .value(PRODUCTION_GROUP_UUID)
      .display("Production")
      .ref(resourceLocationProvider.groupLocation(PRODUCTION_GROUP_UUID))
      .build();
  }

  private void checkAccountHasNoWritableFieldsSet(IamAccount account) {

    assertNotNull(account);
    assertFalse(account.getAttributeByName(TESTUSER_ATTRIBUTE_NAME).isPresent());
    assertFalse(account.getLabelByName(TESTUSER_LABEL_NAME).isPresent());
    assertThat(account.getAuthorities().stream().filter(a -> a.isAdminAuthority()).count(),
        equalTo(0L));
    assertTrue(groupManager.getManagedGroupInfoForAccount(account).getManagedGroups().isEmpty());
  }

  @Test
  public void createUserTest() {

    ScimUser scimUser = ScimUser.builder()
      .active(true)
      .userName(TESTUSER_USERNAME) // mandatory
      .password(TESTUSER_PASSWORD)
      .name(TESTUSER_NAME) // mandatory
      .addEmail(TESTUSER_EMAIL) // mandatory
      .addPhoto(TESTUSER_PHOTO)
      .addOidcId(TESTUSER_OIDCID)
      .addSamlId(TESTUSER_SAMLID)
      .addSshKey(TESTUSER_SSHKEY)
      .build();

    userService.create(scimUser);

    IamAccount account = accountRepo.findByUsername(scimUser.getUserName())
      .orElseThrow(() -> new AssertionError("Expected user not found by policyRepo"));

    assertNotNull(account);

    assertThat(account.isActive(), equalTo(true));

    assertThat(account.getUsername(), equalTo(TESTUSER_USERNAME));

    assertTrue(passwordEncoder.matches(TESTUSER_PASSWORD, account.getPassword()));

    assertThat(account.getUserInfo().getGivenName(), equalTo(TESTUSER_NAME.getGivenName()));
    assertThat(account.getUserInfo().getMiddleName(), equalTo(TESTUSER_NAME.getMiddleName()));
    assertThat(account.getUserInfo().getFamilyName(), equalTo(TESTUSER_NAME.getFamilyName()));

    assertThat(account.getUserInfo().getPicture(), equalTo(TESTUSER_PHOTO.getValue()));

    assertThat(account.getUserInfo().getEmail(), equalTo(TESTUSER_EMAIL.getValue()));

    IamOidcId oidcId = account.getOidcIds().iterator().next();
    assertThat(oidcId.getIssuer(), equalTo(TESTUSER_OIDCID.getIssuer()));
    assertThat(oidcId.getSubject(), equalTo(TESTUSER_OIDCID.getSubject()));

    IamSamlId samlId = account.getSamlIds().iterator().next();

    assertThat(samlId.getIdpId(), equalTo(TESTUSER_SAMLID.getIdpId()));
    assertThat(samlId.getUserId(), equalTo(TESTUSER_SAMLID.getUserId()));

    IamSshKey sshKey = account.getSshKeys().iterator().next();

    assertThat(sshKey.getLabel(), equalTo(TESTUSER_SSHKEY.getDisplay()));
    assertThat(sshKey.getFingerprint(), equalTo(SshKeyUtils.sshKeys.get(0).fingerprintSHA256));
    assertThat(sshKey.getValue(), equalTo(TESTUSER_SSHKEY.getValue()));
    assertThat(sshKey.isPrimary(), equalTo(TESTUSER_SSHKEY.isPrimary()));

    assertTrue(account.getAttributes().isEmpty());
    assertTrue(account.getLabels().isEmpty());

    assertThat(account.getAuthorities().size(), equalTo(1));
    assertThat(account.getAuthorities().stream().findFirst().get().getAuthority(),
        equalTo("ROLE_USER"));
    assertThat(account.getAuthorities().stream().filter(a -> a.isGroupManagerAuthority()).count(),
        equalTo(0L));
    assertThat(account.getAuthorities().stream().filter(a -> a.isAdminAuthority()).count(),
        equalTo(0L));

    assertTrue(groupManager.getManagedGroupInfoForAccount(account).getManagedGroups().isEmpty());

    userService.delete(account.getUuid());
  }

  @Test
  public void createAndReplaceUserCheckingNotWritableFieldsAreIgnoredTest() {

    ScimUser scimUser = ScimUser.builder()
      .userName(TESTUSER_USERNAME) // mandatory
      .addEmail(TESTUSER_EMAIL) // mandatory
      .name(TESTUSER_NAME) // mandatory
      .addAttribute(TESTUSER_ATTRIBUTE) // not writable
      .addLabel(TESTUSER_LABEL) // not writable
      .addManagedGroup(TESTUSER_GROUP_REF) // not writable
      .addAuthority("ROLE_ADMIN") // not writable
      .build();

    userService.create(scimUser);

    IamAccount account = accountRepo.findByUsername(scimUser.getUserName())
      .orElseThrow(() -> new AssertionError("Expected user not found by policyRepo"));

    checkAccountHasNoWritableFieldsSet(account);

    userService.replace(account.getUuid(), scimUser);

    account = accountRepo.findByUsername(scimUser.getUserName())
      .orElseThrow(() -> new AssertionError("Expected user not found by policyRepo"));

    checkAccountHasNoWritableFieldsSet(account);

    userService.delete(account.getUuid());
  }
}
