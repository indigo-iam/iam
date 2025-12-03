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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNotNull;
import java.util.List;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.audit.IamAuditEventLogger;
import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.account.x509.X509CertificateAddedEvent;
import it.infn.mw.iam.audit.events.account.x509.X509CertificateRemovedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK,
    properties = {"notification.certificateUpdate = true",
        "notification.admin-notification-policy = notify-address"})
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
@Transactional
public class CertificateLinkingNotificationAddressEnabledTests extends X509TestSupport
    implements CertificateLinkingNotificationUtil {

  private static final String USERNAME = "event_user";
  private static final String GIVENNAME = "Event";
  private static final String FAMILYNAME = "User";
  private static final String EMAIL = "event_user@localhost";

  private static final String USERNAME_MESSAGE_CHECK = String.format("username: '%s'", USERNAME);

  @Autowired
  private IamAuditEventLogger logger;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private ScimUserProvisioning userProvisioning;
  @Autowired
  private IamEmailNotificationRepository emailRepo;

  @Autowired
  private IamProperties properties;

  @Autowired
  private AdminNotificationDeliveryStrategy adminNotificationDeliveryStrategy;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  private IamAccount account;
  private ScimUser user;

  @Before
  public void setup() {

    ScimX509Certificate test1Cert = ScimX509Certificate.builder()
      .pemEncodedCertificate(TEST_1_CERT_STRING)
      .display(TEST_1_CERT_LABEL)
      .build();

    user = ScimUser.builder(USERNAME)
      .buildName(GIVENNAME, FAMILYNAME)
      .buildEmail(EMAIL)
      .addX509Certificate(test1Cert)
      .build();

    user = userProvisioning.create(user);
    account = accountService.findByUuid(user.getId()).orElseThrow(IllegalArgumentException::new);

    assertNotNull(account);

    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    userProvisioning.delete(account.getUuid());
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testAddX509CertificateEventNotificationPolicy() {


    ScimX509Certificate cert = ScimX509Certificate.builder()
      .pemEncodedCertificate(TEST_0_CERT_STRING)
      .display(TEST_0_CERT_LABEL)
      .subjectDn(TEST_0_SUBJECT)
      .issuerDn(TEST_0_ISSUER)
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

    List<IamEmailNotification> pending = emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

    Assert.assertEquals(1, pending.size());

    Assert.assertEquals(pending.get(0).getBody(),
        getLinkMessage(account.getUserInfo().getName(), account.getUsername(),
            account.getUserInfo().getEmail(), TEST_0_SUBJECT, TEST_0_ISSUER,
            properties.getOrganisation().getName()));

    List<String> receivers = pending.stream()
      .flatMap(n -> n.getReceivers().stream())
      .map(r -> r.getEmailAddress())
      .toList();

    assertThat(adminNotificationDeliveryStrategy.resolveAdminEmailAddresses(), equalTo(receivers));
  }

  @Test
  public void testRemoveX509CertificateEventEventNotificationPolicy() {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .pemEncodedCertificate(TEST_1_CERT_STRING)
      .display(TEST_1_CERT_LABEL)
      .subjectDn(TEST_1_SUBJECT)
      .issuerDn(TEST_1_ISSUER)
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

    List<IamEmailNotification> pending = emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

    Assert.assertEquals(1, pending.size());

    Assert.assertEquals(pending.get(0).getBody(),
        getUnLinkMessage(account.getUserInfo().getName(), account.getUsername(),
            account.getUserInfo().getEmail(), TEST_1_SUBJECT, TEST_1_ISSUER,
            properties.getOrganisation().getName()));

    List<String> receivers = pending.stream()
      .flatMap(n -> n.getReceivers().stream())
      .map(r -> r.getEmailAddress())
      .toList();

    assertThat(adminNotificationDeliveryStrategy.resolveAdminEmailAddresses(), equalTo(receivers));
  }
}
