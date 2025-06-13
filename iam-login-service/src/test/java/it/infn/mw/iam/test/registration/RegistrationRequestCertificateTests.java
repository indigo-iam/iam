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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.X509CertificateChainParser;
import it.infn.mw.iam.authn.x509.X509CertificateChainParsingResult;
import it.infn.mw.iam.authn.x509.X509CertificateVerificationResult;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.RequireCertificateOption;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.DefaultRegistrationRequestService;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.registration.RegistrationRequestService;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class RegistrationRequestCertificateTests {


    @Autowired
    private DefaultRegistrationRequestService defaultRegistrationRequestService;

    @Autowired
    private IamProperties iamProperties;

    @Autowired
    private HttpServletRequest httpRequest;

    @Autowired
    private X509CertificateChainParser parser;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    public static final String TEST_0_SUBJECT = "CN=test0,O=IGI,C=IT";
    public static final String TEST_0_ISSUER = "CN=Test CA,O=IGI,C=IT";
    private static final String TEST_0_CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDnjCCAoagAwIBAgIBCTANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM\n"
            + "MAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTEyMDkyNjE1MzkzNFoX\n"
            + "DTIyMDkyNDE1MzkzNFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoTA0lHSTEOMAwG\n"
            + "A1UEAxMFdGVzdDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKxtrw\n"
            + "hoZ27SxxISjlRqWmBWB6U+N/xW2kS1uUfrQRav6auVtmtEW45J44VTi3WW6Y113R\n"
            + "BwmS6oW+3lzyBBZVPqnhV9/VkTxLp83gGVVvHATgGgkjeTxIsOE+TkPKAoZJ/QFc\n"
            + "CfPh3WdZ3ANI14WYkAM9VXsSbh2okCsWGa4o6pzt3Pt1zKkyO4PW0cBkletDImJK\n"
            + "2vufuDVNm7Iz/y3/8pY8p3MoiwbF/PdSba7XQAxBWUJMoaleh8xy8HSROn7tF2al\n"
            + "xoDLH4QWhp6UDn2rvOWseBqUMPXFjsUi1/rkw1oHAjMroTk5lL15GI0LGd5dTVop\n"
            + "kKXFbTTYxSkPz1MLAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU\n"
            + "fLdB5+jO9LyWN2/VCNYgMa0jvHEwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG\n"
            + "CCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF\n"
            + "BQcDBDAfBgNVHSMEGDAWgBSRdzZ7LrRp8yfqt/YIi0ojohFJxjAnBgNVHREEIDAe\n"
            + "gRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB\n"
            + "AQANYtWXetheSeVpCfnId9TkKyKTAp8RahNZl4XFrWWn2S9We7ACK/G7u1DebJYx\n"
            + "d8POo8ClscoXyTO2BzHHZLxauEKIzUv7g2GehI+SckfZdjFyRXjD0+wMGwzX7MDu\n"
            + "SL3CG2aWsYpkBnj6BMlr0P3kZEMqV5t2+2Tj0+aXppBPVwzJwRhnrSJiO5WIZAZf\n"
            + "49YhMn61sQIrepvhrKEUR4XVorH2Bj8ek1/iLlgcmFMBOds+PrehSRR8Gn0IjlEg\n"
            + "C68EY6KPE+FKySuS7Ur7lTAjNdddfdAgKV6hJyST6/dx8ymIkb8nxCPnxCcT2I2N\n"
            + "vDxcPMc/wmnMa+smNal0sJ6m\n" + "-----END CERTIFICATE-----";




    @Test
    public void testVerifySucessRegisterCertificate() throws Exception {

        String username = "esteban";
        String email = username + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(username);
        request.setNotes("Some short notes...");
        request.setPassword("password");
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


        iamProperties.getRegistration().setRequireCertificate(RequireCertificateOption.REQUIRED);


        RegistrationRequestDto reg = defaultRegistrationRequestService.createRequest(request,
                Optional.empty(), httpRequest);
        assertNotNull(reg);

    }

    /* @Test
    public void testVerifySucessRegisterCertificate2() throws Exception {
        iamProperties.getRegistration().setRequireCertificate(RequireCertificateOption.REQUIRED);

        String username = "esteban";
        String email = username + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(username);
        request.setNotes("Some short notes...");
        request.setPassword("password");

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

        // @formatter:off
        String response = mvc
        .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString();
        // @formatter:on

    } */

    /* @Test
    public void testRegistrationConfigRequireCertificate() throws Exception {
        Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
        RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
        notesProperties.setReadOnly(true);
        notesProperties.setExternalAuthAttribute("notes");
        notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
        fieldAttribute.put("notes", notesProperties);

        when(registrationProperties.getFields()).thenReturn(fieldAttribute);

    // @formatter:off
    mvc.perform(get("/registration/config"))
      .andExpect(status().isOk())
      .andExpect(content().json("{}"));
    // @formatter:on
    } */



}
