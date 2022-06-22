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
package it.infn.mw.iam.test.audit.event;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.api.scim.provisioning.ScimGroupProvisioning;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.audit.IamAuditEventLogger;
import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.account.group.GroupMembershipAddedEvent;
import it.infn.mw.iam.audit.events.account.group.GroupMembershipRemovedEvent;
import it.infn.mw.iam.audit.events.account.oidc.OidcAccountAddedEvent;
import it.infn.mw.iam.audit.events.account.oidc.OidcAccountRemovedEvent;
import it.infn.mw.iam.audit.events.account.saml.SamlAccountAddedEvent;
import it.infn.mw.iam.audit.events.account.saml.SamlAccountRemovedEvent;
import it.infn.mw.iam.audit.events.account.ssh.SshKeyAddedEvent;
import it.infn.mw.iam.audit.events.account.ssh.SshKeyRemovedEvent;
import it.infn.mw.iam.audit.events.account.x509.X509CertificateAddedEvent;
import it.infn.mw.iam.audit.events.account.x509.X509CertificateRemovedEvent;
import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.test.SshKeyUtils;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class EventTests extends X509TestSupport {

  private static final String USERNAME = "event_user";
  private static final String GIVENNAME = "Event";
  private static final String FAMILYNAME = "User";
  private static final String EMAIL = "event_user@localhost";
  private static final String SAML_IDP = "test_idp";
  private static final String SAML_USER_ID = "test_user_id";
  private static final String OIDC_ISSUER = "test_issuer";
  private static final String OIDC_SUBJECT = "test_subject";
  private static final String SSH_LABEL = "test_label";
  private static final String SSH_KEY = SshKeyUtils.sshKeys.get(0).key;
  private static final String SSH_FINGERPRINT = SshKeyUtils.sshKeys.get(0).fingerprintSHA256;
  private static final String GROUPNAME = "event_group";

  private static final String USERNAME_MESSAGE_CHECK = String.format("username: '%s'", USERNAME);

  @Autowired
  private IamAuditEventLogger logger;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private UserConverter userConverter;

  @Autowired
  private ScimUserProvisioning userProvisioning;

  @Autowired
  private ScimGroupProvisioning groupProvisioning;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  private IamAccount account;
  private ScimGroup group;
  private ScimMemberRef accountRef;

  @Before
  public void setup() {

    group = groupProvisioning.create(ScimGroup.builder(GROUPNAME).build());

    ScimX509Certificate test1Cert = ScimX509Certificate.builder()
      .pemEncodedCertificate(TEST_1_CERT_STRING)
      .display(TEST_1_CERT_LABEL)
      .build();

    ScimUser user = ScimUser.builder(USERNAME)
      .buildName(GIVENNAME, FAMILYNAME)
      .buildEmail(EMAIL)
      .buildSamlId(SAML_IDP, SAML_USER_ID)
      .buildOidcId(OIDC_ISSUER, OIDC_SUBJECT)
      .buildSshKey(SSH_LABEL, SSH_KEY, SSH_FINGERPRINT, true)
      .addX509Certificate(test1Cert)
      .build();


    account = accountService.createAccount(userConverter.entityFromDto(user));

    assertNotNull(account);

    accountRef = ScimMemberRef.builder()
      .display(account.getUsername())
      .value(account.getUuid())
      .ref(scimResourceLocationProvider.userLocation(account.getUuid()))
      .build();

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().add(Lists.newArrayList(accountRef)).build();

    groupProvisioning.update(group.getId(), req.getOperations());
  }

  @After
  public void teardown() {
    userProvisioning.delete(account.getUuid());
    groupProvisioning.delete(group.getId());
  }

  @Test
  public void testAddSamlAccountEvent() {

    ScimUser update = ScimUser.builder()
      .addSamlId(ScimSamlId.builder().attributeId("foo").idpId("bar").userId("test").build())
      .build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().add(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(SamlAccountAddedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Add SAML account to user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("idpId=bar"));
    assertThat(event.getMessage(), containsString("attributeId=foo"));
    assertThat(event.getMessage(), containsString("userId=test"));
  }

  @Test
  public void testRemoveSamlAccountEvent() {

    ScimUser update = ScimUser.builder()
      .addSamlId(ScimSamlId.builder().idpId(SAML_IDP).userId(SAML_USER_ID).build())
      .build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().remove(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(SamlAccountRemovedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Remove SAML account from user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("idpId=" + SAML_IDP));
    assertThat(event.getMessage(),
        containsString("attributeId=" + SamlAttributeNames.eduPersonUniqueId));
    assertThat(event.getMessage(), containsString("userId=" + SAML_USER_ID));
  }

  @Test
  public void testAddOidcAccountEvent() {

    ScimUser update = ScimUser.builder()
      .addOidcId(ScimOidcId.builder().issuer("foo").subject("bar").build())
      .build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().add(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(OidcAccountAddedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Add OpenID Connect account to user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("issuer=foo"));
    assertThat(event.getMessage(), containsString("subject=bar"));
  }

  @Test
  public void testRemoveOidcAccountEvent() {

    ScimUser update = ScimUser.builder()
      .addOidcId(ScimOidcId.builder().issuer(OIDC_ISSUER).subject(OIDC_SUBJECT).build())
      .build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().remove(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(OidcAccountRemovedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Remove OpenID Connect account from user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("issuer=" + OIDC_ISSUER));
    assertThat(event.getMessage(), containsString("subject=" + OIDC_SUBJECT));
  }

  @Test
  public void testAddSshKeyEvent() {

    ScimUser update = ScimUser.builder()
      .addSshKey(ScimSshKey.builder()
        .display("foo")
        .value(SshKeyUtils.sshKeys.get(1).key)
        .fingerprint(SshKeyUtils.sshKeys.get(1).fingerprintSHA256)
        .build())
      .build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().add(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(SshKeyAddedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Add ssh key to user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("label=foo"));
    assertThat(event.getMessage(),
        containsString("fingerprint=" + SshKeyUtils.sshKeys.get(1).fingerprintSHA256));
    assertThat(event.getMessage(), containsString("value=" + SshKeyUtils.sshKeys.get(1).key));
  }

  @Test
  public void testRemoveSshKeyEvent() {

    ScimUser update = ScimUser.builder()
      .addSshKey(ScimSshKey.builder()
        .display(SSH_LABEL)
        .value(SSH_KEY)
        .fingerprint(SSH_FINGERPRINT)
        .build())
      .build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().remove(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(SshKeyRemovedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Remove ssh key from user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("label=" + SSH_LABEL));
    assertThat(event.getMessage(), containsString("fingerprint=" + SSH_FINGERPRINT));
    assertThat(event.getMessage(), containsString("value=" + SSH_KEY));
  }

  @Test
  public void testAddX509CertificateEvent() {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .display(TEST_0_CERT_LABEL)
      .build();

    ScimUser update = ScimUser.builder().addX509Certificate(cert).build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().add(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(X509CertificateAddedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Add x509 certificate to user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("label=" + TEST_0_CERT_LABEL));
    assertThat(event.getMessage(), containsString("subjectDn=" + TEST_0_SUBJECT));
    assertThat(event.getMessage(), containsString("issuerDn=" + TEST_0_ISSUER));
    assertThat(event.getMessage(), containsString("certificate=" + TEST_0_CERT_STRING));
  }

  @Test
  public void testRemoveX509CertificateEvent() {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .pemEncodedCertificate(TEST_1_CERT_STRING)
      .display(TEST_1_CERT_LABEL)
      .build();

    ScimUser update = ScimUser.builder().addX509Certificate(cert).build();

    ScimUserPatchRequest req = ScimUserPatchRequest.builder().remove(update).build();
    userProvisioning.update(account.getUuid(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(X509CertificateRemovedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(), containsString("Remove x509 certificate from user"));
    assertThat(event.getMessage(), containsString(USERNAME_MESSAGE_CHECK));
    assertThat(event.getMessage(), containsString("label=" + TEST_1_CERT_LABEL));
    assertThat(event.getMessage(), containsString("subjectDn=" + TEST_1_SUBJECT));
    assertThat(event.getMessage(), containsString("issuerDn=" + TEST_1_ISSUER));
    assertThat(event.getMessage(), containsString("certificate=" + TEST_1_CERT_STRING));
  }

  @Test
  public void testAddGroupMembershipEvent() {

    ScimGroup secondGroup = groupProvisioning.create(ScimGroup.builder("second_group").build());

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().add(Lists.newArrayList(accountRef)).build();

    groupProvisioning.update(secondGroup.getId(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(GroupMembershipAddedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(),
        containsString("User 'event_user' was added to group 'second_group'"));
  }

  @Test
  public void testRemoveGroupMembershipEvent() {

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().remove(Lists.newArrayList(accountRef)).build();

    groupProvisioning.update(group.getId(), req.getOperations());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(GroupMembershipRemovedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(),
        containsString("User 'event_user' was removed from group 'event_group'"));

  }

}
