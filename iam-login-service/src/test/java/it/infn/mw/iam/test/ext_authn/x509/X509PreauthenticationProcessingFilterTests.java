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
package it.infn.mw.iam.test.ext_authn.x509;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;


import static org.hamcrest.Matchers.notNullValue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter;
import it.infn.mw.iam.authn.x509.X509AuthenticationCredentialExtractor;
import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;


@AutoConfigureMockMvc
@SpringBootTest(properties = "iam.registration.fields.certificate.field-behaviour = OPTIONAL")
class X509PreauthenticationProcessingFilterTests {

    private static final String TEST_0_SUBJECT = "CN=test0,O=IGI,C=IT";
    private static final String TEST_0_ISSUER = "CN=Test CA,O=IGI,C=IT";

    // "Sat Sep 24 17:39:34 CEST 2022"
    private static final Date TEST_0_END_DATE = new Date(1664033974000L);
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

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private X509AuthenticationCredentialExtractor credentialExtractor;

    @MockBean
    private IamX509CertificateRepository certificateRepo;

    @Test
    void x509_filter_is_triggered_when_credential_is_present() throws Exception {

        IamX509AuthenticationCredential cred = mock(IamX509AuthenticationCredential.class);

        when(cred.failedVerification()).thenReturn(false);
        when(cred.getSubject()).thenReturn(TEST_0_SUBJECT);
        when(cred.getIssuer()).thenReturn(TEST_0_ISSUER);
        X509Certificate userCert = loadTestCertificate();

        when(cred.getCertificateChain()).thenReturn(new X509Certificate[] {userCert});

        when(credentialExtractor.extractX509Credential(any())).thenReturn(Optional.of(cred));

        IamAccount account = mock(IamAccount.class);
        when(account.isActive()).thenReturn(true);

        IamX509Certificate cert = mock(IamX509Certificate.class);
        when(cert.getAccount()).thenReturn(account);

        when(certificateRepo.findBySubjectDnAndIssuerDn(any(), any()))
            .thenReturn(Optional.of(cert));

        mockMvc.perform(get("/").param("x509ClientAuth", "true"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login**"))
            .andExpect(request()
                .attribute(IamX509PreauthenticationProcessingFilter.X509_ALMOST_EXPIRED, true))
            .andExpect(request().sessionAttribute(
                    IamX509PreauthenticationProcessingFilter.X509_ALMOST_EXPIRED, true))
            .andExpect(request().attribute(IamX509PreauthenticationProcessingFilter.X509_REQUIRED,
                    ExternalAuthAttributeSectionBehaviour.OPTIONAL))
            .andExpect(request().sessionAttribute(
                    IamX509PreauthenticationProcessingFilter.X509_REQUIRED,
                    ExternalAuthAttributeSectionBehaviour.OPTIONAL))
            .andExpect(request().attribute(
                    IamX509PreauthenticationProcessingFilter.X509_EXPIRATION_DATE, TEST_0_END_DATE))
            .andExpect(request().sessionAttribute(
                    IamX509PreauthenticationProcessingFilter.X509_EXPIRATION_DATE, TEST_0_END_DATE))
            .andExpect(request().sessionAttribute(
                    IamX509PreauthenticationProcessingFilter.X509_CREDENTIAL_SESSION_KEY,
                    notNullValue()));

        verify(certificateRepo).findBySubjectDnAndIssuerDn(TEST_0_SUBJECT, TEST_0_ISSUER);
    }

    private static X509Certificate loadTestCertificate() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(TEST_0_CERT.getBytes(StandardCharsets.US_ASCII)));
    }
}
