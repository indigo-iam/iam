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

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.stereotype.Component;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account_linking.DefaultAccountLinkingService;
import it.infn.mw.iam.api.proxy.DefaultProxyCertificateService;
import it.infn.mw.iam.api.proxy.ProxyCertificateProperties;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.PEMX509CertificateChainParser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;
import it.infn.mw.iam.rcauth.x509.DefaultProxyHelperService;
import it.infn.mw.iam.rcauth.x509.ProxyHelperService;
import it.infn.mw.iam.api.proxy.ProxyCertificateRequestDTO;
import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;



// Why am I doing all of this??

// Shouldn't I just fetch an account, have a certificate, link the two and check if the email is pending?

// Small detail I need to set the 'IAM_NOTIFICATION_CERTIFICATE' to true and check if it happens

// Then I have to set it to false and ensure that it doesn't happen


/* @RunWith( SpringJUnit4ClassRunner.class )
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.NONE) */
@RunWith(MockitoJUnitRunner.class)
@WithMockUser(username = "test", roles = "USER")
//@ComponentScan({"it.infn.mw.iam.api.account_linking"})
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

    public static final Instant NOW = Instant.parse("2019-01-01T00:00:00.00Z");
    public static final String TEST_USER_USERNAME = "test";
    public static final long DEFAULT_PROXY_LIFETIME_SECONDS = TimeUnit.HOURS.toSeconds(12);
    protected Clock clock = Clock.fixed(NOW, ZoneId.systemDefault());
    public static final String TEST_0_CERT_PATH = "src/test/resources/x509/test0.cert.pem";


    ProxyHelperService proxyHelper = new DefaultProxyHelperService(clock);
    X509TestSupport x509TestSupport = new X509TestSupport();

    IamAccount somebody = new IamAccount();

    @Before
    public void setup() {

        // Configuring the certificate
        proxyService =
                new DefaultProxyCertificateService(clock, repo, properties, proxyHelper);
        when(principal.getName()).thenReturn(TEST_USER_USERNAME);
        //when(account.getUsername()).thenReturn(TEST_USER_USERNAME);
        //when(properties.getMaxLifetimeSeconds()).thenReturn(DEFAULT_PROXY_LIFETIME_SECONDS);
        //when(request.getLifetimeSecs()).thenReturn(null);

        // Setting up the DefaultAccountLinkingService
        linkingService.setApplicationEventPublisher(eventPublisher);
        
        //Setting up the necessary support methods for the certificate
        x509TestSupport.mockHttpRequestWithTest0SSLHeaders(httpRequest);

        //Configuring the user
        IamAccount somebody = new IamAccount();
        somebody.setId(Long.valueOf(420));
        somebody.setUsername("test");

        //Handling the instance where the user is called upon from the repository
        when(repo.findByUsername(somebody.getUsername())).thenReturn(Optional.of(somebody) );
        

        

    }



    // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is true
    @Test
    public void notificationwhenLinkingCertificatePositive() {

        //Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(true);

        IamX509AuthenticationCredential credentials = extractor.extractX509Credential(httpRequest)
            .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));


        linkingService.linkX509Certificate(principal, credentials);

        verify(notificationFactory,times(1)).createLinkedCertificateMessage(somebody,credentials);

    }

    // When the user is linking the certificate and the IAM_NOTIFICATION_CERTIFICATE is false
    @Test
    public void notificationwhenLinkingCertificateNegative() {

        //Setting the IAM_NOTIFICATION_CERTIFICATE to true
        when(notificationProperties.getCertificateUpdate()).thenReturn(false);

        IamX509AuthenticationCredential credentials = extractor.extractX509Credential(httpRequest)
            .orElseThrow(() -> new AssertionError("Credential not found when one was expected"));


        linkingService.linkX509Certificate(principal, credentials);

        verify(notificationFactory,times(0)).createLinkedCertificateMessage(somebody,credentials);

    }



}
