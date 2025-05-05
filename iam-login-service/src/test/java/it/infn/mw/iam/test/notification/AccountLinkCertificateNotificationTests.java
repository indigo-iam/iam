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
package it.infn.mw.iam.test.notification;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.junit4.SpringRunner;


import it.infn.mw.iam.api.account_linking.DefaultAccountLinkingService;
import it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.X509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParserImpl;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.NotificationProperties.AdminNotificationPolicy;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.test.SshKeyUtils;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;



@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AccountLinkCertificateNotificationTests extends X509TestSupport {


        @Mock
        private HttpServletRequest httpRequest;

        @Mock
        private Principal principal;

        @Autowired
        private DefaultAccountLinkingService linkingService;

        @Autowired
        private ApplicationEventPublisher eventPublisher;


        @Autowired
        private NotificationProperties notificationProperties;

        @Autowired
        private IamEmailNotificationRepository emailRepo;

        @Autowired
        private IamProperties iamProperties;

        @Autowired
        private AdminNotificationDeliveryStrategy adminNotificationDeliveryStrategy;

        @Autowired
        private IamAccountService accountService;

        @Autowired
        private UserConverter userConverter;


        private X509CertificateChainParser certChainParser = new X509CertificateChainParserImpl();



        DefaultX509AuthenticationCredentialExtractor extractor =
                        new DefaultX509AuthenticationCredentialExtractor(certChainParser);


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

        private IamAccount account;


        @Before
        public void setup() {

                when(principal.getName()).thenReturn(USERNAME);

                // Setting up the DefaultAccountLinkingService
                linkingService.setApplicationEventPublisher(eventPublisher);

                // Setting up the necessary support methods for the certificate
                mockHttpRequestWithTest0SSLHeaders(httpRequest);


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


        }



        // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
        @Test
        public void notificationwhenLinkingCertificatePositive() {

                notificationProperties
                        .setAdminNotificationPolicy(AdminNotificationPolicy.NOTIFY_ADMINS);
                notificationProperties.setCertificateUpdate(true);

                IamX509AuthenticationCredential credentials = extractor
                        .extractX509Credential(httpRequest)
                        .orElseThrow(() -> new AssertionError(
                                        "Credential not found when one was expected"));


                linkingService.linkX509Certificate(principal, credentials);

                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(1, pending.size());
                assertThat(pending.get(0).getSubject(),
                                containsString(notificationProperties.getSubjectPrefix()
                                                + " New x509Certificate linked to user"));

                assertThat(pending.get(0).getReceivers().get(0).getEmailAddress(),
                                containsString(adminNotificationDeliveryStrategy
                                        .resolveAdminEmailAddresses()
                                        .get(0)));
                assertThat(pending.get(0).getBody(), containsString(
                                "The following user has linked a certificate to their account."));
                assertThat(pending.get(0).getBody(),
                                containsString("Name: " + GIVENNAME + " " + FAMILYNAME));
                assertThat(pending.get(0).getBody(), containsString("Username: " + USERNAME));
                assertThat(pending.get(0).getBody(), containsString("Email: " + EMAIL));
                assertThat(pending.get(0).getBody(),
                                containsString("SubjectDN: " + TEST_0_SUBJECT));
                assertThat(pending.get(0).getBody(), containsString("IssuerDN: " + TEST_0_ISSUER));
                assertThat(pending.get(0).getBody(),
                                containsString("The " + iamProperties.getOrganisation().getName()
                                                + " registration service"));


        }



        // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
        @Test
        public void notificationwhenLinkingCertificateAlternativeAdminNotificationPositive() {


                notificationProperties.setCertificateUpdate(true);
                notificationProperties.setAdminNotificationPolicy(
                                AdminNotificationPolicy.NOTIFY_ADDRESS_AND_ADMINS);

                IamX509AuthenticationCredential credentials = extractor
                        .extractX509Credential(httpRequest)
                        .orElseThrow(() -> new AssertionError(
                                        "Credential not found when one was expected"));


                linkingService.linkX509Certificate(principal, credentials);

                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(1, pending.size());
                assertThat(pending.get(0).getSubject(),
                                containsString(notificationProperties.getSubjectPrefix()
                                                + " New x509Certificate linked to user"));

                assertThat(pending.get(0).getReceivers().get(0).getEmailAddress(),
                                containsString(adminNotificationDeliveryStrategy
                                        .resolveAdminEmailAddresses()
                                        .get(0)));
                assertThat(pending.get(0).getBody(), containsString(
                                "The following user has linked a certificate to their account."));
                assertThat(pending.get(0).getBody(),
                                containsString("Name: " + GIVENNAME + " " + FAMILYNAME));
                assertThat(pending.get(0).getBody(), containsString("Username: " + USERNAME));
                assertThat(pending.get(0).getBody(), containsString("Email: " + EMAIL));
                assertThat(pending.get(0).getBody(),
                                containsString("SubjectDN: " + TEST_0_SUBJECT));
                assertThat(pending.get(0).getBody(), containsString("IssuerDN: " + TEST_0_ISSUER));
                assertThat(pending.get(0).getBody(),
                                containsString("The " + iamProperties.getOrganisation().getName()
                                                + " registration service"));

        }

        // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is false
        @Test
        public void notificationwhenLinkingCertificateNegative() {


                notificationProperties
                        .setAdminNotificationPolicy(AdminNotificationPolicy.NOTIFY_ADMINS);
                notificationProperties.setCertificateUpdate(false);

                IamX509AuthenticationCredential credentials = extractor
                        .extractX509Credential(httpRequest)
                        .orElseThrow(() -> new AssertionError(
                                        "Credential not found when one was expected"));


                linkingService.linkX509Certificate(principal, credentials);

                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(pending.size(), 0);

        }

        // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true,
        // but
        // wrong notification policy
        @Test
        public void notificationwhenLinkingCertificateWrongNotificationPolicy() {


                notificationProperties
                        .setAdminNotificationPolicy(AdminNotificationPolicy.NOTIFY_ADDRESS);
                notificationProperties.setCertificateUpdate(true);


                IamX509AuthenticationCredential credentials = extractor
                        .extractX509Credential(httpRequest)
                        .orElseThrow(() -> new AssertionError(
                                        "Credential not found when one was expected"));


                linkingService.linkX509Certificate(principal, credentials);

                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(pending.size(), 0);

        }

        // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
        @Test
        public void notificationwhenUnlinkingCertificatePositive() {

                notificationProperties
                        .setAdminNotificationPolicy(AdminNotificationPolicy.NOTIFY_ADMINS);
                notificationProperties.setCertificateUpdate(true);

                linkingService.unlinkX509Certificate(principal, TEST_1_SUBJECT);

                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(1, pending.size());

                assertThat(pending.get(0).getSubject(),
                                containsString(notificationProperties.getSubjectPrefix()
                                                + " Removed x509Certificate from user"));

                assertThat(pending.get(0).getReceivers().get(0).getEmailAddress(),
                                containsString(adminNotificationDeliveryStrategy
                                        .resolveAdminEmailAddresses()
                                        .get(0)));
                assertThat(pending.get(0).getBody(), containsString(
                                "The following user has removed a previously linked a certificate from their account."));
                assertThat(pending.get(0).getBody(),
                                containsString("Name: " + GIVENNAME + " " + FAMILYNAME));
                assertThat(pending.get(0).getBody(), containsString("Username: " + USERNAME));
                assertThat(pending.get(0).getBody(), containsString("Email: " + EMAIL));
                assertThat(pending.get(0).getBody(),
                                containsString("SubjectDN: " + TEST_1_SUBJECT));
                assertThat(pending.get(0).getBody(), containsString("IssuerDN: " + TEST_1_ISSUER));
                assertThat(pending.get(0).getBody(),
                                containsString("The " + iamProperties.getOrganisation().getName()
                                                + " registration service"));


        }

        // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
        @Test
        public void notificationwhenUnlinkingCertificateAlternativeAdminNotificationPositive() {

                notificationProperties.setAdminNotificationPolicy(
                                AdminNotificationPolicy.NOTIFY_ADDRESS_AND_ADMINS);
                notificationProperties.setCertificateUpdate(true);



                linkingService.unlinkX509Certificate(principal, TEST_1_SUBJECT);
                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(1, pending.size());

                assertThat(pending.get(0).getSubject(),
                                containsString(notificationProperties.getSubjectPrefix()
                                                + " Removed x509Certificate from user"));

                assertThat(pending.get(0).getReceivers().get(0).getEmailAddress(),
                                containsString(adminNotificationDeliveryStrategy
                                        .resolveAdminEmailAddresses()
                                        .get(0)));
                assertThat(pending.get(0).getBody(), containsString(
                                "The following user has removed a previously linked a certificate from their account."));
                assertThat(pending.get(0).getBody(),
                                containsString("Name: " + GIVENNAME + " " + FAMILYNAME));
                assertThat(pending.get(0).getBody(), containsString("Username: " + USERNAME));
                assertThat(pending.get(0).getBody(), containsString("Email: " + EMAIL));
                assertThat(pending.get(0).getBody(),
                                containsString("SubjectDN: " + TEST_1_SUBJECT));
                assertThat(pending.get(0).getBody(), containsString("IssuerDN: " + TEST_1_ISSUER));
                assertThat(pending.get(0).getBody(),
                                containsString("The " + iamProperties.getOrganisation().getName()
                                                + " registration service"));



        }


        // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is false
        @Test
        public void notificationwhenUnlinkingCertificateFalse() {

                notificationProperties
                        .setAdminNotificationPolicy(AdminNotificationPolicy.NOTIFY_ADMINS);
                notificationProperties.setCertificateUpdate(false);


                linkingService.unlinkX509Certificate(principal, TEST_1_SUBJECT);

                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(0, pending.size());



        }

        // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
        @Test
        public void notificationwhenUnlinkingCertificateWrongNotificationPolicy() {

                notificationProperties
                        .setAdminNotificationPolicy(AdminNotificationPolicy.NOTIFY_ADDRESS);
                notificationProperties.setCertificateUpdate(true);


                linkingService.unlinkX509Certificate(principal, TEST_1_SUBJECT);

                List<IamEmailNotification> pending =
                                emailRepo.findByDeliveryStatus(IamDeliveryStatus.PENDING);

                Assert.assertEquals(0, pending.size());



        }



}
