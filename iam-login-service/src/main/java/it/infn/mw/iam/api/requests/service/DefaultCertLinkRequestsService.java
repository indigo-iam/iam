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
import it.infn.mw.iam.api.requests.model.CertLinkRequestDto;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestApprovedEvent;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestCreatedEvent;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestDeletedEvent;
import it.infn.mw.iam.audit.events.cert_link.request.CertLinkRequestRejectedEvent;
import it.infn.mw.iam.core.IamRequestStatus;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
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

  private static final Table<IamRequestStatus, IamRequestStatus, Boolean> ALLOWED_STATE_TRANSITIONS =
      new ImmutableTable.Builder<IamRequestStatus, IamRequestStatus, Boolean>()
        .put(PENDING, APPROVED, true)
        .put(PENDING, REJECTED, true)
        .build();

  @Override
  public CertLinkRequestDto createCertLinkRequest(CertLinkRequestDto requestDto) {

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new IllegalStateException("No authenticated user found"));

    requestDto.setUserUuid(account.getUuid());
    requestDto.setUsername(account.getUsername());

    certLinkRequestUtils.checkRequestAlreadyExist(requestDto);
    certLinkRequestUtils.checkCertAlreadyLinked(requestDto, account);
    certLinkRequestUtils.checkCertNotLinkedToSomeoneElse(requestDto, account);

    IamX509Certificate cert = x509CertificateRepository
      .findBySubjectDnAndIssuerDn(requestDto.getSubjectDn(), requestDto.getIssuerDn())
      .orElseGet(() -> x509CertificateRepository.save(converter.certificateFromRequest(requestDto)));

    IamCertLinkRequest request = new IamCertLinkRequest();
    request.setUuid(UUID.randomUUID().toString());
    request.setAccount(account);
    request.setCertificate(cert);
    request.setNotes(requestDto.getNotes());
    request.setStatus(PENDING);
    Date creationTime = new Date(timeProvider.currentTimeMillis());
    request.setCreationTime(creationTime);
    request.setLastUpdateTime(creationTime);

    request = certLinkRequestRepository.save(request);
    notificationFactory.createAdminHandleCertLinkRequestMessage(request);
    eventPublisher.publishEvent(new CertLinkRequestCreatedEvent(this, request));

    return converter.dtoFromEntity(request);
  }

  @Override
  public void deleteCertLinkRequest(String requestId) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);

    certLinkRequestRepository.deleteById(request.getId());
    eventPublisher.publishEvent(new CertLinkRequestDeletedEvent(this, request));
  }

  @Override
  public CertLinkRequestDto approveCertLinkRequest(String requestId) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);

    IamAccount account = request.getAccount();
    IamX509Certificate cert = request.getCertificate();

    account.linkX509Certificates(List.of(cert));

    request = updateCertLinkRequestStatus(request, APPROVED);
    notificationFactory.createCertLinkApprovedMessage(request);
    eventPublisher.publishEvent(new CertLinkRequestApprovedEvent(this, request));

    return converter.dtoFromEntity(request);
  }

  @Override
  public CertLinkRequestDto rejectCertLinkRequest(String requestId, String motivation) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);
    certLinkRequestUtils.validateRejectMotivation(motivation);

    request.setMotivation(motivation);
    request = updateCertLinkRequestStatus(request, REJECTED);
    notificationFactory.createCertLinkRejectedMessage(request);
    eventPublisher.publishEvent(new CertLinkRequestRejectedEvent(this, request));

    return converter.dtoFromEntity(request);
  }

  @Override
  public CertLinkRequestDto getCertLinkRequestDetails(String requestId) {
    IamCertLinkRequest request = certLinkRequestUtils.getCertLinkRequest(requestId);
    return converter.dtoFromEntity(request);
  }

  @Override
  public ListResponseDTO<CertLinkRequestDto> listCertLinkRequests(String username, String subject,
      String status, OffsetPageable pageRequest) {
    Optional<String> usernameFilter = Optional.ofNullable(username);
    Optional<String> subjectFilter = Optional.ofNullable(subject);
    Optional<String> statusFilter = Optional.ofNullable(status);

    List<CertLinkRequestDto> results = Lists.newArrayList();

    Page<IamCertLinkRequest> pagedResults =
        lookupCertLinkRequests(usernameFilter, subjectFilter, statusFilter, pageRequest);

    pagedResults.getContent().forEach(request -> results.add(converter.dtoFromEntity(request)));

    ListResponseDTO.Builder<CertLinkRequestDto> builder = ListResponseDTO.builder();
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
    return certLinkRequestRepository.save(request);
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
