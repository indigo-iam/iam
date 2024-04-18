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
package it.infn.mw.iam.test.api.cert_link_requests;

import static it.infn.mw.iam.core.IamRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamRequestStatus.PENDING;
import static it.infn.mw.iam.core.IamRequestStatus.REJECTED;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.requests.CertLinkRequestConverter;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.core.IamRequestStatus;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamCertLinkRequestRepository;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;

public class CertLinkRequestsTestUtils {

  protected final static String TEST_ADMIN = "admin";
  protected final static String TEST_ADMIN_UUID = "73f16d93-2441-4a50-88ff-85360d78c6b5";
  protected final static String TEST_ADMIN_FULL_NAME = "Admin User";
  protected final static String TEST_100_USERNAME = "test_100";
  protected final static String TEST_101_USERNAME = "test_101";
  protected final static String TEST_102_USERNAME = "test_102";
  protected final static String TEST_103_USERNAME = "test_103";
  protected final static String TEST_SUBJECTDN_OK = "CN=Test100,O=Test";
  protected final static String TEST_ISSUERDN_OK = "CN=Test CA,O=IGI,C=IT";

  protected final static String TEST_NOTES = "Test certLink request membership";
  protected final static String TEST_REJECT_MOTIVATION = "You are not welcome!";
  protected final static String TEST0_PEM_STRING = "-----BEGIN CERTIFICATE-----\n" + //
      "MIIDnjCCAoagAwIBAgIBCDANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM\n" + //
      "MAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTIyMTAwMTEzMTYzMloX\n" + //
      "DTMyMDkyODEzMTYzMlowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoMA0lHSTEOMAwG\n" + //
      "A1UEAwwFdGVzdDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoyIIN\n" + //
      "H7YaqKMIW4kI41E0gDqtaQKYKdCv1cDL9/ibg0QLO/hyak9u9zQnp7XlK6e9NwnM\n" + //
      "T3efn3o5xWyA4nY8UWvXQRxQjuQO1hxManxFxzVHYYkd5p4JDy3lrDSPgw8yojPZ\n" + //
      "iAwVcDWZfVzXEC/EEAtbheSZcydQaEWSCLmY9rrriyvxrIlYaiAzXFhV0hRsxPy9\n" + //
      "Fk85nq1JVzeAN7jVt3JVrDgHd17IQIySXz3JU7UYChGcW3CO4LNe4p39cbjW6wbi\n" + //
      "Uqo+7caSJsOxwoS2RcHAahgd+BGegMkr48krmojuDcYrrkAL4AK0Uh5xXdWul1kG\n" + //
      "0SFf0WyN23CjuFEXAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU\n" + //
      "aognKvxLiK8OSA1F/9x+7qCDtuUwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG\n" + //
      "CCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF\n" + //
      "BQcDBDAfBgNVHSMEGDAWgBRQm290AeMaA1er2dV9FWRMJfP49DAnBgNVHREEIDAe\n" + //
      "gRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB\n" + //
      "AQBHBk5Pcr3EXJZedPeEQuXCdPMDAJpAcZTCTINfGRoQXDYQk6ce8bH8jHPmao6d\n" + //
      "qV/f/14y2Jmkz+aiFQhSSyDLk4ywTgGHT+kpWEsYGbN4AdcMlH1L9uaG7YbuAZzH\n" + //
      "6bkd8HLsTiwslXYHjyldbQL9ZU6DrGAdt/IuAfFrQjWWuJ21SfBlnp4OkWQK5wTk\n" + //
      "sTvfeZX6VwinpXzF6xIrtAfJ7OYRDuN7UIrwBl9G0hoQPuXFJeVRAzYRwDVbejSo\n" + //
      "/8OWCj17EXDO+tG6Md+JYIsqJ4wrytd4YeuYDVDzbVV8DHfMrk2+PeJ0nSOSyYV+\n" + //
      "doaFzJ6837vw8+5gxDTHT/un\n" + //
      "-----END CERTIFICATE-----\n";

  @Autowired
  protected IamCertLinkRequestRepository certLinkRequestRepository;

  @Autowired
  protected IamAccountRepository accountRepository;

  @Autowired
  protected IamX509CertificateRepository certificateRepository;

  @Autowired
  protected CertLinkRequestConverter converter;

  @Autowired
  protected ObjectMapper mapper;

  @Autowired
  protected CertLinkRequestConverter certLinkRequestConverter;

  protected CertLinkRequestDTO buildCertLinkRequest(String label, String subjectDn, String issuerDn,
      String pemString) {
    CertLinkRequestDTO request = new CertLinkRequestDTO();
    request.setLabel(label);
    request.setSubjectDn(subjectDn);
    request.setIssuerDn(issuerDn);
    request.setPemEncodedCertificate(pemString);
    request.setNotes(TEST_NOTES);

    return request;
  }

  protected CertLinkRequestDTO savePendingCertLinkRequest(String username, String subjectDn,
      String issuerDn, String pemString) {
    return saveCertLinkRequest(username, subjectDn, issuerDn, pemString, PENDING);
  }

  protected CertLinkRequestDTO saveApprovedCertLinkRequest(String username, String subjectDn,
      String issuerDn, String pemString) {
    return saveCertLinkRequest(username, subjectDn, issuerDn, pemString, APPROVED);
  }

  protected CertLinkRequestDTO saveRejectedCertLinkRequest(String username, String subjectDn,
      String issuerDn, String pemString) {
    return saveCertLinkRequest(username, subjectDn, issuerDn, pemString, REJECTED);
  }

  private CertLinkRequestDTO saveCertLinkRequest(String username, String subjectDn, String issuerDn,
      String pemString, IamRequestStatus status) {

    IamX509Certificate cert = new IamX509Certificate();
    cert.setLabel("Test Certificate");
    cert.setSubjectDn(subjectDn);
    cert.setIssuerDn(issuerDn);
    cert.setCertificate(pemString);
    cert.setCreationTime(new Date());
    cert.setLastUpdateTime(new Date());

    IamCertLinkRequest iamCertLinkRequest = new IamCertLinkRequest();
    iamCertLinkRequest.setUuid(UUID.randomUUID().toString());
    iamCertLinkRequest.setAccount(accountRepository.findByUsername(username).get());
    iamCertLinkRequest.setCertificate(cert);
    iamCertLinkRequest.setNotes(TEST_NOTES);
    iamCertLinkRequest.setStatus(status);
    iamCertLinkRequest.setCreationTime(new Date());
    if (REJECTED.equals(status)) {
      iamCertLinkRequest.setMotivation(TEST_REJECT_MOTIVATION);
    }

    IamCertLinkRequest result = certLinkRequestRepository.save(iamCertLinkRequest);

    return converter.dtoFromEntity(result);
  }

  public void linkAccountToCert(String username, CertLinkRequestDTO requestDTO) {
    IamX509Certificate cert = converter.certificateFromRequest(requestDTO);
    accountRepository.findByUsername(username).ifPresent(account -> {
      account.linkX509Certificates(List.of(cert));
      certificateRepository.save(cert);
    });

  }
}
