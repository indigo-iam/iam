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
package it.infn.mw.iam.test.registration;

import static it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter.X509_CREDENTIAL_SESSION_KEY;
import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.core.user.exception.CredentialAlreadyBoundException;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.security.auth.login.AccountNotFoundException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.X509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParsingResult;
import it.infn.mw.iam.authn.x509.X509CertificateVerificationResult;
import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.config.IamProperties.RegistrationField;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.DefaultRegistrationRequestService;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
        properties = "iam.registration.fields.certificate.field-behaviour = OPTIONAL")
public class RegistrationRequestCertificateOptionalTests {

    @Autowired
    private DefaultRegistrationRequestService defaultRegistrationRequestService;

    @Autowired
    private HttpServletRequest httpRequest;

    @Autowired
    private X509CertificateChainParser parser;

    @Autowired
    private IamAccountRepository iamAccountRepo;

    @Autowired
    private IamRegistrationRequestRepository iamRequestRepo;

    @Autowired
    private MockMvc mvc;

    @MockBean
    private RegistrationProperties registrationProperties;

    private static final String USERNAME = "esteban";
    private static final String USERNAME_2 = "carlos";
    public static final String TEST_0_SUBJECT = "CN=test0,O=IGI,C=IT";
    public static final String TEST_0_ISSUER = "CN=Test CA,O=IGI,C=IT";
    public static final String TEST_1_SUBJECT = "C=IT, O=IGI, CN=test1";
    public static final String TEST_1_ISSUER = "C=IT, O=IGI, CN=test1";
    private static final String TEST_0_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIDnjCCAoagAwIBAgIBCTANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM
            MAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTEyMDkyNjE1MzkzNFoX
            DTIyMDkyNDE1MzkzNFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoTA0lHSTEOMAwG
            A1UEAxMFdGVzdDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKxtrw
            hoZ27SxxISjlRqWmBWB6U+N/xW2kS1uUfrQRav6auVtmtEW45J44VTi3WW6Y113R
            BwmS6oW+3lzyBBZVPqnhV9/VkTxLp83gGVVvHATgGgkjeTxIsOE+TkPKAoZJ/QFc
            CfPh3WdZ3ANI14WYkAM9VXsSbh2okCsWGa4o6pzt3Pt1zKkyO4PW0cBkletDImJK
            2vufuDVNm7Iz/y3/8pY8p3MoiwbF/PdSba7XQAxBWUJMoaleh8xy8HSROn7tF2al
            xoDLH4QWhp6UDn2rvOWseBqUMPXFjsUi1/rkw1oHAjMroTk5lL15GI0LGd5dTVop
            kKXFbTTYxSkPz1MLAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU
            fLdB5+jO9LyWN2/VCNYgMa0jvHEwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG
            CCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF
            BQcDBDAfBgNVHSMEGDAWgBSRdzZ7LrRp8yfqt/YIi0ojohFJxjAnBgNVHREEIDAe
            gRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB
            AQANYtWXetheSeVpCfnId9TkKyKTAp8RahNZl4XFrWWn2S9We7ACK/G7u1DebJYx
            d8POo8ClscoXyTO2BzHHZLxauEKIzUv7g2GehI+SckfZdjFyRXjD0+wMGwzX7MDu
            SL3CG2aWsYpkBnj6BMlr0P3kZEMqV5t2+2Tj0+aXppBPVwzJwRhnrSJiO5WIZAZf
            49YhMn61sQIrepvhrKEUR4XVorH2Bj8ek1/iLlgcmFMBOds+PrehSRR8Gn0IjlEg
            C68EY6KPE+FKySuS7Ur7lTAjNdddfdAgKV6hJyST6/dx8ymIkb8nxCPnxCcT2I2N
            vDxcPMc/wmnMa+smNal0sJ6m
            -----END CERTIFICATE-----""";

    private static final String TEST_1_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIDkDCCAnigAwIBAgIUIRiHqEUe9NMkryEsI23CTkMamdgwDQYJKoZIhvcNAQEL
            BQAwLDELMAkGA1UEBhMCSVQxDDAKBgNVBAoMA0lHSTEPMA0GA1UEAwwGdGVzdDAx
            MB4XDTI1MDcwMTEzMjgwMFoXDTM1MDYyOTEzMjgwMFowLDELMAkGA1UEBhMCSVQx
            DDAKBgNVBAoMA0lHSTEPMA0GA1UEAwwGdGVzdDAxMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA2RuUgUXeAFM9/wOiAMrhttRp2zImtZVRkYFNwawPVxve
            5SCENZjEivQ3f1PtmFGxG0YboZGu0dR2n9MV3GGNFJkrhAet7fAwoZr8BvoQaEjr
            yC9I5z3fpwwwabfpsFPe04CeWfXHmSMQoHLXYQqxLi8etzcJZ1tsBT1yAUwbkqNx
            95bgl4FBaU7iv+jqdxf4aoa5n8QUeM0+CtM/RSQQLQtlKItQRyib8MxYDeRcc3pB
            VaysLLj1I0bsVZgFM7Qg/2oftsQAMiRqRM0byz2VNBvuaSgZ3gZpOyB/+0P/SGPK
            WHnxLZMV/Wy5RDckoG4zHVIxIiEeYDD0txnhLsNIxwIDAQABo4GpMIGmMAwGA1Ud
            EwQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTMwWkWHGWur+WQk7BR
            VNguNPY5MDBnBgNVHSMEYDBegBTMwWkWHGWur+WQk7BRVNguNPY5MKEwpC4wLDEL
            MAkGA1UEBhMCSVQxDDAKBgNVBAoMA0lHSTEPMA0GA1UEAwwGdGVzdDAxghQhGIeo
            RR700ySvISwjbcJOQxqZ2DANBgkqhkiG9w0BAQsFAAOCAQEApWB8P+CQCeJCsOKA
            65DBE6jCoXS1He+iG5eFfw/GuKZhRe7zLZsObAH+DKqbjkCLsHsRoEUo8EPErmvY
            GDE58Zrv8fsqakcNseRBcLHgBmPiZgDEIk3yd9S/3mAFaY4D7KLb/2uOHSBc72Ax
            C3zYT8VA6C7wEiSW+Fg9gbXwMb34Xj6xGIm2+74iogwrQd9l2geyfSLirpUvZe24
            otjNLk3d7XQ1mSjiUx+6+blzwdIkaoVjbS0WsYOdtaPo+wuPGQieyzWvnIdOl8sd
            9ovNoFyB1LkUaWImlLucqRKdhuAy/e+9lurYpQ1uft86ep1p6pimEmb7bOQYcKEo
            jARH0w==
            -----END CERTIFICATE-----""";

    @Test
    public void testVerifySucessRegisterCertificate() throws Exception {

        String email = USERNAME + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(USERNAME);
        request.setNotes("Some short notes...");
        request.setRegisterCertificate("true");

        HttpSession session = httpRequest.getSession();

        X509CertificateChainParsingResult result = parser.parseChainFromString(TEST_0_CERT);

        IamX509AuthenticationCredential test0Cred = IamX509AuthenticationCredential.builder()
            .certificateChain(result.getChain())
            .certificateChainPemString(result.getPemString())
            .subject(TEST_0_SUBJECT)
            .issuer(TEST_0_ISSUER)
            .verificationResult(X509CertificateVerificationResult.success())
            .build();

        httpRequest.setAttribute(X509_CREDENTIAL_SESSION_KEY, test0Cred);
        session.setAttribute(X509_CREDENTIAL_SESSION_KEY, test0Cred);

        RegistrationRequestDto reg = defaultRegistrationRequestService.createRequest(request,
                Optional.empty(), httpRequest);
        assertNotNull(reg);

        List<IamRegistrationRequest> requests =
                iamRequestRepo.findByStatus(IamRegistrationRequestStatus.NEW)
                    .orElseThrow(() -> new AccountNotFoundException(
                            "Can not remove suspended account as none is found"));

        assertEquals(1, requests.size());

        for (IamRegistrationRequest iamRegistrationRequest : requests) {
            iamRequestRepo.delete(iamRegistrationRequest);
        }

        IamAccount account =
                iamAccountRepo.findByUsername(USERNAME).orElseThrow(AccountNotFoundException::new);

        assertTrue(account.getX509Certificates()
            .stream()
            .anyMatch(c -> c.getCertificate().contentEquals(TEST_0_CERT)));

        iamAccountRepo.delete(account);
    }

    @Test
    public void testVerifySucessRegisterCertificate2() throws Exception {

        String email = USERNAME_2 + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test2");
        request.setFamilyname("User2");
        request.setEmail(email);
        request.setUsername(USERNAME_2);
        request.setNotes("Some short notes...");
        request.setRegisterCertificate("true");

        HttpSession session = httpRequest.getSession();

        X509CertificateChainParsingResult result = parser.parseChainFromString(TEST_1_CERT);

        IamX509AuthenticationCredential test1Cred = IamX509AuthenticationCredential.builder()
            .certificateChain(result.getChain())
            .certificateChainPemString(result.getPemString())
            .subject(TEST_1_SUBJECT)
            .issuer(TEST_1_ISSUER)
            .verificationResult(X509CertificateVerificationResult.success())
            .build();

        httpRequest.setAttribute(X509_CREDENTIAL_SESSION_KEY, test1Cred);

        session.setAttribute(X509_CREDENTIAL_SESSION_KEY, test1Cred);

        RegistrationRequestDto reg = defaultRegistrationRequestService.createRequest(request,
                Optional.empty(), httpRequest);
        assertNotNull(reg);

        List<IamRegistrationRequest> requests =
                iamRequestRepo.findByStatus(IamRegistrationRequestStatus.NEW)
                    .orElseThrow(() -> new AccountNotFoundException(
                            "Can not remove suspended account as none is found"));

        assertEquals(1, requests.size());

        for (IamRegistrationRequest iamRegistrationRequest : requests) {
            iamRequestRepo.delete(iamRegistrationRequest);
        }

        IamAccount account = iamAccountRepo.findByUsername(USERNAME_2)
            .orElseThrow(AccountNotFoundException::new);

        assertTrue(account.getX509Certificates()
            .stream()
            .anyMatch(c -> c.getCertificate().contentEquals(TEST_1_CERT)));

        iamAccountRepo.delete(account);
    }

    @Test
    public void testVerifySucessRegisterNoCertificate() throws Exception {

        String email = USERNAME_2 + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test2");
        request.setFamilyname("User2");
        request.setEmail(email);
        request.setUsername(USERNAME_2);
        request.setNotes("Some short notes...");
        request.setRegisterCertificate("false");

        HttpSession session = httpRequest.getSession();

        X509CertificateChainParsingResult result = parser.parseChainFromString(TEST_1_CERT);

        IamX509AuthenticationCredential test1Cred = IamX509AuthenticationCredential.builder()
            .certificateChain(result.getChain())
            .certificateChainPemString(result.getPemString())
            .subject(TEST_1_SUBJECT)
            .issuer(TEST_1_ISSUER)
            .verificationResult(X509CertificateVerificationResult.success())
            .build();

        httpRequest.setAttribute(X509_CREDENTIAL_SESSION_KEY, test1Cred);

        session.setAttribute(X509_CREDENTIAL_SESSION_KEY, test1Cred);

        RegistrationRequestDto reg = defaultRegistrationRequestService.createRequest(request,
                Optional.empty(), httpRequest);
        assertNotNull(reg);

        List<IamRegistrationRequest> requests =
                iamRequestRepo.findByStatus(IamRegistrationRequestStatus.NEW)
                    .orElseThrow(() -> new AccountNotFoundException(
                            "Can not remove suspended account as none is found"));

        assertEquals(1, requests.size());

        for (IamRegistrationRequest iamRegistrationRequest : requests) {
            iamRequestRepo.delete(iamRegistrationRequest);
        }

        IamAccount account = iamAccountRepo.findByUsername(USERNAME_2)
            .orElseThrow(AccountNotFoundException::new);

        assertFalse(account.getX509Certificates()
            .stream()
            .anyMatch(c -> c.getCertificate().contentEquals(TEST_1_CERT)));

        iamAccountRepo.delete(account);
    }

    @Test
    public void testVerifyErrorRegisterSameCertificate() throws Exception {

        String email = USERNAME + "@example.org";
        final RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(USERNAME);
        request.setNotes("Some short notes...");
        request.setRegisterCertificate("true");

        HttpSession session = httpRequest.getSession();

        X509CertificateChainParsingResult result = parser.parseChainFromString(TEST_0_CERT);

        IamX509AuthenticationCredential test0Cred = IamX509AuthenticationCredential.builder()
            .certificateChain(result.getChain())
            .certificateChainPemString(result.getPemString())
            .subject(TEST_0_SUBJECT)
            .issuer(TEST_0_ISSUER)
            .verificationResult(X509CertificateVerificationResult.success())
            .build();

        httpRequest.setAttribute(X509_CREDENTIAL_SESSION_KEY, test0Cred);

        session.setAttribute(X509_CREDENTIAL_SESSION_KEY, test0Cred);

        RegistrationRequestDto reg = defaultRegistrationRequestService.createRequest(request,
                Optional.empty(), httpRequest);
        assertNotNull(reg);

        email = USERNAME_2 + "@example.org";
        request.setEmail(email);
        request.setUsername(USERNAME_2);
        request.setRegisterCertificate("true");

        httpRequest.getSession();

        Optional<ExternalAuthenticationRegistrationInfo> optional = Optional.empty();

        org.junit.jupiter.api.Assertions.assertThrows(CredentialAlreadyBoundException.class,
                () -> defaultRegistrationRequestService.createRequest(request, optional,
                        httpRequest));

        List<IamRegistrationRequest> requests =
                iamRequestRepo.findByStatus(IamRegistrationRequestStatus.NEW)
                    .orElseThrow(() -> new AccountNotFoundException(
                            "Can not remove suspended account as none is found"));

        assertEquals(1, requests.size());

        Optional<IamAccount> invalidAccount = iamAccountRepo.findByUsername(USERNAME_2);

        assertFalse(invalidAccount.isPresent());

        for (IamRegistrationRequest iamRegistrationRequest : requests) {
            iamRequestRepo.delete(iamRegistrationRequest);
        }

        IamAccount account =
                iamAccountRepo.findByUsername(USERNAME).orElseThrow(AccountNotFoundException::new);

        assertTrue(account.getX509Certificates()
            .stream()
            .anyMatch(c -> c.getCertificate().contentEquals(TEST_0_CERT)));

        iamAccountRepo.delete(account);
    }

    @Test
    public void testVerifyMultipleRegisterCertificate() throws Exception {

        String email = USERNAME + "@example.org";
        final RegistrationRequestDto request1 = new RegistrationRequestDto();
        request1.setGivenname("Test");
        request1.setFamilyname("User");
        request1.setEmail(email);
        request1.setUsername(USERNAME);
        request1.setNotes("Some short notes...");
        request1.setRegisterCertificate("true");

        MockHttpServletRequest req1 = new MockHttpServletRequest();
        MockHttpSession session1 = new MockHttpSession();
        req1.setSession(session1);

        X509CertificateChainParsingResult result1 = parser.parseChainFromString(TEST_0_CERT);

        IamX509AuthenticationCredential test0Cred = IamX509AuthenticationCredential.builder()
            .certificateChain(result1.getChain())
            .certificateChainPemString(result1.getPemString())
            .subject(TEST_0_SUBJECT)
            .issuer(TEST_0_ISSUER)
            .verificationResult(X509CertificateVerificationResult.success())
            .build();

        req1.setAttribute(X509_CREDENTIAL_SESSION_KEY, test0Cred);
        session1.setAttribute(X509_CREDENTIAL_SESSION_KEY, test0Cred);

        RegistrationRequestDto reg =
                defaultRegistrationRequestService.createRequest(request1, Optional.empty(), req1);
        assertNotNull(reg);

        String email2 = USERNAME_2 + "@example.org";
        final RegistrationRequestDto request2 = new RegistrationRequestDto();
        request2.setGivenname("Test2");
        request2.setFamilyname("User2");
        request2.setEmail(email2);
        request2.setUsername(USERNAME_2);
        request2.setNotes("Some short notes...");
        request2.setRegisterCertificate("true");

        MockHttpServletRequest req2 = new MockHttpServletRequest();
        MockHttpSession session2 = new MockHttpSession();
        req2.setSession(session2);

        X509CertificateChainParsingResult result2 = parser.parseChainFromString(TEST_1_CERT);

        IamX509AuthenticationCredential test1Cred = IamX509AuthenticationCredential.builder()
            .certificateChain(result2.getChain())
            .certificateChainPemString(result2.getPemString())
            .subject(TEST_1_SUBJECT)
            .issuer(TEST_1_ISSUER)
            .verificationResult(X509CertificateVerificationResult.success())
            .build();

        req2.setAttribute(X509_CREDENTIAL_SESSION_KEY, test1Cred);
        session2.setAttribute(X509_CREDENTIAL_SESSION_KEY, test1Cred);

        Optional<ExternalAuthenticationRegistrationInfo> optional = Optional.empty();

        reg = defaultRegistrationRequestService.createRequest(request2, optional, req2);
        assertNotNull(reg);

        List<IamRegistrationRequest> requests =
                iamRequestRepo.findByStatus(IamRegistrationRequestStatus.NEW)
                    .orElseThrow(() -> new AccountNotFoundException(
                            "Can not remove suspended account as none is found"));

        assertEquals(2, requests.size());

        for (IamRegistrationRequest iamRegistrationRequest : requests) {
            iamRequestRepo.delete(iamRegistrationRequest);
        }

        IamAccount account =
                iamAccountRepo.findByUsername(USERNAME).orElseThrow(AccountNotFoundException::new);

        assertTrue(account.getX509Certificates()
            .stream()
            .anyMatch(c -> c.getCertificate().contentEquals(TEST_0_CERT)));

        iamAccountRepo.delete(account);

        account = iamAccountRepo.findByUsername(USERNAME_2)
            .orElseThrow(AccountNotFoundException::new);

        assertTrue(account.getX509Certificates()
            .stream()
            .anyMatch(c -> c.getCertificate().contentEquals(TEST_1_CERT)));

        iamAccountRepo.delete(account);
    }

    @Test
    public void testRegistrationConfigRequireCertificate() throws Exception {
        Map<RegistrationField, RegistrationFieldProperties> fieldAttribute =
                new EnumMap<>(RegistrationField.class);
        RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
        RegistrationField registrationField = RegistrationField.CERTIFICATE;
        notesProperties.setReadOnly(true);
        notesProperties.setExternalAuthAttribute("notes");
        notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
        fieldAttribute.put(registrationField, notesProperties);

        when(registrationProperties.getFields()).thenReturn(fieldAttribute);

    // @formatter:off
    mvc.perform(get("/registration/config"))
      .andExpect(status().isOk())
      .andExpect(content().json("{}"));
    // @formatter:on
    }
}
