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
package it.infn.mw.iam.api.requests.service;

import static it.infn.mw.iam.core.IamRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamRequestStatus.PENDING;
import static it.infn.mw.iam.core.IamRequestStatus.REJECTED;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import com.google.common.collect.ImmutableTable;
import com.google.common.collect.Lists;
import com.google.common.collect.Table;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.requests.CertLinkRequestConverter;
import it.infn.mw.iam.api.requests.CertLinkRequestUtils;
import it.infn.mw.iam.api.requests.exception.InvalidIamRequestStatusError;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.audit.events.account.x509.X509CertificateAddedEvent;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestApprovedEvent;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestCreatedEvent;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestDeletedEvent;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestRejectedEvent;
import it.infn.mw.iam.core.IamRequestStatus;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamCertLinkRequestRepository;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;

@Service
public class DefaultCertLinkRequestsService implements CertLinkRequestsService {

  @Autowired
  public IamCertLinkRequestRepository certLinkRequestRepository;

  @Autowired
  private CertLinkRequestConverter converter;

  @Autowired
  private AccountUtils accountUtils;

  @Autowired
  private CertLinkRequestUtils certLinkRequestUtils;

  @Autowired
  private NotificationFactory notificationFactory;

  @Autowired
  private TimeProvider timeProvider;

  @Autowired
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  private IamX509CertificateRepository x509CertificateRepository;

  private static final IamAuthority ROLE_ADMIN = new IamAuthority("ROLE_ADMIN");

  private static final Table<IamRequestStatus, IamRequestStatus, Boolean> ALLOWED_STATE_TRANSITIONS = new ImmutableTable.Builder<IamRequestStatus, IamRequestStatus, Boolean>()
      .put(PENDING, APPROVED, true)
      .put(PENDING, REJECTED, true)
      .build();

  @Override
  public CertLinkRequestDTO createCertLinkRequest(CertLinkRequestDTO requestDto) {

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
        .orElseThrow(() -> new IllegalStateException("No authenticated user found"));

    requestDto.setUserUuid(account.getUuid());
    requestDto.setUsername(account.getUsername());

    IamX509Certificate newCert = converter.certificateFromRequest(requestDto);
    IamX509Certificate cert = x509CertificateRepository
        .findBySubjectDnAndIssuerDn(newCert.getSubjectDn(),
            newCert.getIssuerDn())
        .orElse(newCert);

    certLinkRequestUtils.checkCertAlreadyLinked(cert, account);
    certLinkRequestUtils.checkCertNotLinkedToSomeoneElse(cert, account);

    IamCertLinkRequest request = new IamCertLinkRequest();
    request.setUuid(UUID.randomUUID().toString());
    request.setAccount(account);
    request.setCertificate(cert);
    request.setNotes(requestDto.getNotes());
    request.setStatus(PENDING);
    Date creationTime = new Date(timeProvider.currentTimeMillis());
    request.setCreationTime(creationTime);
    request.setLastUpdateTime(creationTime);

    certLinkRequestUtils.checkRequestAlreadyExist(request);

    request = certLinkRequestRepository.save(request);
    notificationFactory.createAdminHandleCertLinkRequestMessage(request);
    eventPublisher.publishEvent(new CertLinkRequestCreatedEvent(this, request));

    return converter.dtoFromEntity(request);
  }

  @Override
  public void deleteCertLinkRequest(String requestId) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);

    certLinkRequestRepository.deleteById(request.getId());
    x509CertificateRepository.delete(request.getCertificate());
    eventPublisher.publishEvent(new CertLinkRequestDeletedEvent(this, request));
  }

  @Override
  public CertLinkRequestDTO approveCertLinkRequest(String requestId) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);
    
    IamAccount account = request.getAccount();
    IamX509Certificate cert = request.getCertificate();
    certLinkRequestUtils.checkCertAlreadyLinked(cert, account);
    certLinkRequestUtils.checkCertNotLinkedToSomeoneElse(cert, account);
    
    updateCertLinkRequestStatus(request, APPROVED);
    notificationFactory.createCertLinkApprovedMessage(request);
    eventPublisher.publishEvent(new CertLinkRequestApprovedEvent(this, request));
    certLinkRequestRepository.delete(request);

    account.linkX509Certificates(List.of(cert));
    x509CertificateRepository.save(cert);
    eventPublisher.publishEvent(new X509CertificateAddedEvent(this, account, List.of(cert)));

    return converter.dtoFromEntity(request);
  }

  @Override
  public CertLinkRequestDTO rejectCertLinkRequest(String requestId, String motivation) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);
    certLinkRequestUtils.validateRejectMotivation(motivation);

    request.setMotivation(motivation);
    updateCertLinkRequestStatus(request, REJECTED);
    notificationFactory.createCertLinkRejectedMessage(request);
    eventPublisher.publishEvent(new CertLinkRequestRejectedEvent(this, request));
    certLinkRequestRepository.delete(request);

    return converter.dtoFromEntity(request);
  }

  @Override
  public CertLinkRequestDTO getCertLinkRequestDetails(String requestId) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);
    return converter.dtoFromEntity(request);
  }

  @Override
  public ListResponseDTO<CertLinkRequestDTO> listCertLinkRequests(String username, String subject,
      String status, OffsetPageable pageRequest) {
    Optional<String> usernameFilter = Optional.ofNullable(username);
    Optional<String> subjectFilter = Optional.ofNullable(subject);
    Optional<String> statusFilter = Optional.ofNullable(status);

    IamAccount userAccount = accountUtils.getAuthenticatedUserAccount()
        .orElseThrow(() -> new IllegalStateException("No authenticated user found"));
    if (!userAccount.getAuthorities().contains(ROLE_ADMIN)) {
      usernameFilter = Optional.of(userAccount.getUsername());
    }    

    List<CertLinkRequestDTO> results = Lists.newArrayList();

    Page<IamCertLinkRequest> pagedResults = lookupCertLinkRequests(usernameFilter, subjectFilter, statusFilter,
        pageRequest);

    pagedResults.getContent().forEach(request -> results.add(converter.dtoFromEntity(request)));

    ListResponseDTO.Builder<CertLinkRequestDTO> builder = ListResponseDTO.builder();
    return builder.resources(results).fromPage(pagedResults, pageRequest).build();
  }

  private IamCertLinkRequest updateCertLinkRequestStatus(IamCertLinkRequest request,
      IamRequestStatus status) {

    if (!ALLOWED_STATE_TRANSITIONS.contains(request.getStatus(), status)) {
      throw new InvalidIamRequestStatusError(String
          .format("Invalid certLink request transition: %s -> %s", request.getStatus(), status));
    }
    request.setStatus(status);
    request.setLastUpdateTime(new Date(timeProvider.currentTimeMillis()));
    return request;
  }

  static Specification<IamCertLinkRequest> baseSpec() {
    return (req, cq, cb) -> cb.conjunction();
  }

  static Specification<IamCertLinkRequest> forUser(String username) {
    return (req, cq, cb) -> cb.equal(req.get("account").get("username"), username);
  }

  static Specification<IamCertLinkRequest> forSubject(String subject) {
    return (req, cq, cb) -> cb.equal(req.get("certificate").get("subjectDn"), subject);
  }

  static Specification<IamCertLinkRequest> withStatus(String status) {
    return (req, cq, cb) -> cb.equal(req.get("status"), IamRequestStatus.valueOf(status));
  }

  private Page<IamCertLinkRequest> lookupCertLinkRequests(Optional<String> usernameFilter,
      Optional<String> subjectFilter, Optional<String> statusFilter, OffsetPageable pageRequest) {

    Specification<IamCertLinkRequest> spec = baseSpec();

    if (usernameFilter.isPresent()) {
      spec = spec.and(forUser(usernameFilter.get()));
    }

    if (subjectFilter.isPresent()) {
      spec = spec.and(forSubject(subjectFilter.get()));
    }

    if (statusFilter.isPresent()) {
      spec = spec.and(withStatus(statusFilter.get()));
    }

    return certLinkRequestRepository.findAll(spec, pageRequest);
  }

}
