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
        properties = "iam.registration.fields.certificate.field-behaviour=MANDATORY")
public class RegistrationRequestCertificateTests {


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

        for (IamRegistrationRequest iamRegistrationRequest : requests) {
            iamRequestRepo.delete(iamRegistrationRequest);
        }

        IamAccount account =
                iamAccountRepo.findByUsername(USERNAME).orElseThrow(AccountNotFoundException::new);

        iamAccountRepo.delete(account);


    }

    @Test
    public void testVerifySanityError() throws Exception {

        String email = USERNAME + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(USERNAME);
        request.setNotes("Some short notes...");
        request.setRegisterCertificate("true");

        httpRequest.getSession();

        X509CertificateChainParsingResult result = parser.parseChainFromString(TEST_0_CERT);

        IamX509AuthenticationCredential test0Cred = IamX509AuthenticationCredential.builder()
            .certificateChain(result.getChain())
            .certificateChainPemString(result.getPemString())
            .subject(TEST_0_SUBJECT)
            .issuer(TEST_0_ISSUER)
            .verificationResult(X509CertificateVerificationResult.success())
            .build();

        httpRequest.setAttribute(X509_CREDENTIAL_SESSION_KEY, test0Cred);


        org.junit.jupiter.api.Assertions.assertThrows(
                it.infn.mw.iam.api.scim.exception.IllegalArgumentException.class,
                () -> defaultRegistrationRequestService.createRequest(request, Optional.empty(),
                        httpRequest));



        List<IamRegistrationRequest> requests =
                iamRequestRepo.findByStatus(IamRegistrationRequestStatus.NEW)
                    .orElseThrow(() -> new AccountNotFoundException(
                            "Can not remove suspended account as none is found"));

        assertEquals(0, requests.size());

        assertFalse(iamAccountRepo.findByUsername(USERNAME).isPresent());
    }


    @Test
    public void testVerifyErrorRegisterCertificate() throws Exception {

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

        for (IamRegistrationRequest iamRegistrationRequest : requests) {
            iamRequestRepo.delete(iamRegistrationRequest);
        }

        IamAccount account =
                iamAccountRepo.findByUsername(USERNAME).orElseThrow(AccountNotFoundException::new);

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
