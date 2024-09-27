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
package it.infn.mw.iam.api.requests;

import static it.infn.mw.iam.core.IamRequestStatus.PENDING;
import static java.lang.String.format;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.requests.exception.IamRequestValidationError;
import it.infn.mw.iam.core.IamRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamCertLinkRequestRepository;

@Component
public class CertLinkRequestUtils {

  @Autowired
  private IamCertLinkRequestRepository certLinkRequestRepository;

  @Autowired
  private IamAccountRepository accountRepository;

  public Optional<IamCertLinkRequest> getOptionalCertLinkRequest(String uuid) {
    return certLinkRequestRepository.findByUuid(uuid);
  }

  public IamCertLinkRequest getCertLinkRequest(String requestId) {
    return certLinkRequestRepository.findByUuid(requestId)
        .orElseThrow(() -> new IamRequestValidationError(
            String.format("CertLink request with UUID [%s] does not exist", requestId)));
  }

  public void checkRequestAlreadyExist(IamCertLinkRequest request) {

    List<IamCertLinkRequest> results = certLinkRequestRepository
        .findByAccountAndDns(request.getAccount().getUuid(), request.getCertificate().getSubjectDn(),
            request.getCertificate().getIssuerDn());

    for (IamCertLinkRequest r : results) {
      IamRequestStatus status = r.getStatus();

      if (PENDING.equals(status)) {
        throw new IamRequestValidationError(
            String.format("CertLink request already exists for user %s and certificate [%s | %s]",
                request.getAccount().getUsername(), request.getCertificate().getSubjectDn(),
                request.getCertificate().getIssuerDn()));
      }
    }
  }

  public void validateRejectMotivation(String motivation) {
    String value = motivation;
    if (motivation != null) {
      value = motivation.trim();
    }

    if (Strings.isNullOrEmpty(value)) {
      throw new IamRequestValidationError("Reject motivation cannot be empty");
    }
  }

  public void checkCertAlreadyLinked(IamX509Certificate requestCert, IamAccount userAccount) {
    Optional<IamX509Certificate> linkedCerts = userAccount.getX509Certificates()
        .stream()
        .filter(
            c -> c.getSubjectDn().equals(requestCert.getSubjectDn())
                && c.getIssuerDn().equals(requestCert.getIssuerDn()))
        .findAny();

    if (linkedCerts.isPresent()) {
      throw new IamRequestValidationError(
          String.format("User %s is already linked to the certificate [%s | %s]", userAccount.getUsername(),
              requestCert.getSubjectDn(), requestCert.getIssuerDn()));
    }
  }

  public void checkCertNotLinkedToSomeoneElse(IamX509Certificate requestCert, IamAccount userAccount) {
    accountRepository.findByCertificateSubject(requestCert.getSubjectDn()).ifPresent(linkedAccount -> {
      if (!linkedAccount.getUuid().equals(userAccount.getUuid())) {
        throw new IamRequestValidationError(
            format("X.509 credential with subject '%s' is already linked to another user",
                requestCert.getSubjectDn()));
      }
    });
  }
}
