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

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationEventPublisher;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account_linking.DefaultAccountLinkingService;
import it.infn.mw.iam.api.proxy.DefaultProxyCertificateService;
import it.infn.mw.iam.api.proxy.ProxyCertificateProperties;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.PEMX509CertificateChainParser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;
import it.infn.mw.iam.rcauth.x509.DefaultProxyHelperService;
import it.infn.mw.iam.rcauth.x509.ProxyHelperService;
import it.infn.mw.iam.api.proxy.ProxyCertificateRequestDTO;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.NotificationProperties.AdminNotificationPolicy;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;



@RunWith(MockitoJUnitRunner.Silent.class)
public class AccountLinkCertificateNotificationTests {

    @Mock
    ProxyCertificateRequestDTO request;

    @Mock
    HttpServletRequest httpRequest;

    @Mock
    Principal principal;

    @Mock
    IamAccountRepository repo;

    @Mock
    ProxyCertificateProperties properties;


    @InjectMocks
    DefaultAccountLinkingService linkingService;

    @Mock
    IamAccount account;

    @Mock
    IamEmailNotificationRepository notificationRepo;

    @Mock
    IamX509CertificateRepository certificateRepository;

    @Mock
    ApplicationEventPublisher eventPublisher;

    @Mock
    ExternalAccountLinker linker;

    @Mock
    NotificationFactory notificationFactory;

    @Mock
    NotificationProperties notificationProperties;



    DefaultX509AuthenticationCredentialExtractor extractor =
            new DefaultX509AuthenticationCredentialExtractor(new PEMX509CertificateChainParser());



    @Mock
    AccountUtils accountUtils;

    DefaultProxyCertificateService proxyService;

    private static final Instant NOW = Instant.parse("2019-01-01T00:00:00.00Z");
    private static final String TEST_USER_USERNAME = "test";
    private Clock clock = Clock.fixed(NOW, ZoneId.systemDefault());
    private final String CERTIFICATE = "A certificate, but in string form";
    private final String SUBJECTDN = "Waldo";
    private final String USERNAME = "test";


    IamX509Certificate x509Certificate = new IamX509Certificate();

    @Mock
    Set<IamX509Certificate> certificateSet;

    @Mock
    IamAccount somebody;



    private ProxyHelperService proxyHelper = new DefaultProxyHelperService(clock);
    private X509TestSupport x509TestSupport = new X509TestSupport();



    @Before
    public void setup() {

        // Configuring the certificate
        proxyService = new DefaultProxyCertificateService(clock, repo, properties, proxyHelper);
        when(principal.getName()).thenReturn(TEST_USER_USERNAME);

        // Setting up the DefaultAccountLinkingService
        linkingService.setApplicationEventPublisher(eventPublisher);

        // Setting up the necessary support methods for the certificate
        x509TestSupport.mockHttpRequestWithTest0SSLHeaders(httpRequest);


        // Setting up the IamAccount
        when(somebody.getUsername()).thenReturn(USERNAME);
        when(somebody.getX509Certificates()).thenReturn(certificateSet);


        // Setting up the certificate
        x509Certificate.setCertificate(CERTIFICATE);
        x509Certificate.setSubjectDn(SUBJECTDN);


        // Actually having an cerificate set, so it can be iterated over
        Set<IamX509Certificate> realSet = new HashSet<IamX509Certificate>();
        realSet.add(x509Certificate);

        Iterator<IamX509Certificate> iterator = realSet.iterator();



        // Setting up the certificate set
        when(certificateSet.remove(eq(x509Certificate))).thenReturn(true);
        when(certificateSet.iterator()).thenReturn(iterator);


        // Handling the instance where the user is called upon from the repository
        when(repo.findByUsername(somebody.getUsername())).thenReturn(Optional.of(somebody));

    }



    // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
    @Test
    public void notificationwhenLinkingCertificatePositive() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(true);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADMINS);


        IamX509AuthenticationCredential credentials = extractor.extractX509Credential(httpRequest)
            .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));


        linkingService.linkX509Certificate(principal, credentials);

        verify(notificationFactory, times(1)).createLinkedCertificateMessage(somebody, credentials);

    }



    // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
    @Test
    public void notificationwhenLinkingCertificateAlternativeAdminNotificationPositive() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(true);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADDRESS_AND_ADMINS);


        IamX509AuthenticationCredential credentials = extractor.extractX509Credential(httpRequest)
            .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));


        linkingService.linkX509Certificate(principal, credentials);

        verify(notificationFactory, times(1)).createLinkedCertificateMessage(somebody, credentials);

    }

    // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is false
    @Test
    public void notificationwhenLinkingCertificateNegative() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(false);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADMINS);

        IamX509AuthenticationCredential credentials = extractor.extractX509Credential(httpRequest)
            .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));


        linkingService.linkX509Certificate(principal, credentials);

        verify(notificationFactory, times(0)).createLinkedCertificateMessage(somebody, credentials);

    }

    // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true, but
    // wrong notification policy
    @Test
    public void notificationwhenLinkingCertificateWrongNotificationPolicy() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(true);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADDRESS);


        IamX509AuthenticationCredential credentials = extractor.extractX509Credential(httpRequest)
            .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));


        linkingService.linkX509Certificate(principal, credentials);

        verify(notificationFactory, times(0)).createLinkedCertificateMessage(somebody, credentials);

    }

    // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
    @Test
    public void notificationwhenUnlinkingCertificatePositive() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(true);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADMINS);


        linkingService.unlinkX509Certificate(principal, SUBJECTDN);

        verify(notificationFactory, times(1)).createUnlinkedCertificateMessage(somebody,
                x509Certificate);


    }

    // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
    @Test
    public void notificationwhenUnlinkingCertificateAlternativeAdminNotificationPositive() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(true);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADDRESS_AND_ADMINS);


        linkingService.unlinkX509Certificate(principal, SUBJECTDN);

        verify(notificationFactory, times(1)).createUnlinkedCertificateMessage(somebody,
                x509Certificate);


    }


    // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is false
    @Test
    public void notificationwhenUnlinkingCertificateFalse() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(false);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADMINS);


        linkingService.unlinkX509Certificate(principal, SUBJECTDN);

        verify(notificationFactory, times(0)).createUnlinkedCertificateMessage(somebody,
                x509Certificate);


    }

    // When the user is unlinking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
    @Test
    public void notificationwhenUnlinkingCertificateWrongNotificationPolicy() {

        // Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(true);

        // Setting the Notification policy to notify admins
        when(notificationProperties.getAdminNotificationPolicy())
            .thenReturn(AdminNotificationPolicy.NOTIFY_ADDRESS);


        linkingService.unlinkX509Certificate(principal, SUBJECTDN);

        verify(notificationFactory, times(0)).createUnlinkedCertificateMessage(somebody,
                x509Certificate);


    }



}
