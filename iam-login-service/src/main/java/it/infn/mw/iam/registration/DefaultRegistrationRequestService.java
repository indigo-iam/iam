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
package it.infn.mw.iam.registration;

import static com.google.common.base.Preconditions.checkNotNull;
import static it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType.OIDC;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.CONFIRMED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.REJECTED;
import static java.util.Objects.isNull;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.google.common.collect.ImmutableTable;
import com.google.common.collect.Table;

import it.infn.mw.iam.api.common.LabelDTOConverter;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.audit.events.registration.RegistrationApproveEvent;
import it.infn.mw.iam.audit.events.registration.RegistrationConfirmEvent;
import it.infn.mw.iam.audit.events.registration.RegistrationRejectEvent;
import it.infn.mw.iam.audit.events.registration.RegistrationRequestEvent;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.config.lifecycle.LifecycleProperties;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidationService;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidatorError;

@Service
public class DefaultRegistrationRequestService
    implements RegistrationRequestService, ApplicationEventPublisherAware {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultRegistrationRequestService.class);

  @Autowired
  private IamRegistrationRequestRepository requestRepository;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private UserConverter userConverter;

  @Autowired
  private NotificationFactory notificationFactory;

  @Autowired
  private RegistrationConverter converter;

  @Autowired
  private TokenGenerator tokenGenerator;

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private IamAupRepository iamAupRepo;

  @Autowired
  private IamAupSignatureRepository iamAupSignatureRepo;

  @Autowired
  private LabelDTOConverter labelConverter;

  @Autowired(required = false)
  private RegistrationRequestValidationService validationService;

  @Autowired
  private LifecycleProperties lifecycleProperties;

  @Autowired
  private Clock clock;

  private ApplicationEventPublisher eventPublisher;

  private IamRegistrationRequest findRequestById(String requestUuid) {
    return requestRepository.findByUuid(requestUuid)
      .orElseThrow(() -> new ScimResourceNotFoundException(
          String.format("No request mapped to uuid [%s]", requestUuid)));
  }

  private static final Table<IamRegistrationRequestStatus, IamRegistrationRequestStatus, Boolean> allowedStateTransitions =
      new ImmutableTable.Builder<IamRegistrationRequestStatus, IamRegistrationRequestStatus, Boolean>()
        .put(NEW, CONFIRMED, true)
        .put(NEW, APPROVED, true)
        .put(NEW, REJECTED, true)
        .put(CONFIRMED, APPROVED, true)
        .put(CONFIRMED, REJECTED, true)
        .put(APPROVED, CONFIRMED, true)
        .put(REJECTED, CONFIRMED, true)
        .build();


  private void addExternalAuthnInfo(ScimUser.Builder user,
      ExternalAuthenticationRegistrationInfo extAuthnInfo) {

    checkNotNull(extAuthnInfo.getType());
    checkNotNull(extAuthnInfo.getSubject());
    checkNotNull(extAuthnInfo.getIssuer());

    if (OIDC.equals(extAuthnInfo.getType())) {
      ScimOidcId oidcId = new ScimOidcId.Builder().issuer(extAuthnInfo.getIssuer())
        .subject(extAuthnInfo.getSubject())
        .build();
      user.addOidcId(oidcId);
    } else if (ExternalAuthenticationType.SAML.equals(extAuthnInfo.getType())) {
      ScimSamlId samlId = new ScimSamlId.Builder().idpId(extAuthnInfo.getIssuer())
        .userId(extAuthnInfo.getSubject())
        .attributeId(extAuthnInfo.getSubjectAttribute())
        .build();
      user.addSamlId(samlId);
    }
  }

  private void createAupSignatureForAccountIfNeeded(IamAccount account) {
    iamAupRepo.findDefaultAup()
      .ifPresent(
          a -> iamAupSignatureRepo.createSignatureForAccount(account, Date.from(clock.instant())));
  }


  @Override
  public RegistrationRequestDto createRequest(RegistrationRequestDto dto,
      Optional<ExternalAuthenticationRegistrationInfo> extAuthnInfo) {

    notesSanityChecks(dto.getNotes());

    if (!isNull(validationService)) {
      RegistrationRequestValidationResult result =
          validationService.validateRegistrationRequest(dto, extAuthnInfo);

      if (!result.isOk()) {
        LOG.info("Request validation failed: {}", result.getErrorMessage());
        throw new RegistrationRequestValidatorError(result.getErrorMessage());
      }
    }

    ScimUser.Builder userBuilder = ScimUser.builder()
      .buildName(dto.getGivenname(), dto.getFamilyname())
      .buildEmail(dto.getEmail())
      .userName(dto.getUsername())
      .password(dto.getPassword());

    extAuthnInfo.ifPresent(i -> addExternalAuthnInfo(userBuilder, i));

    IamAccount accountEntity =
        accountService.createAccount(userConverter.entityFromDto(userBuilder.build()));
    accountEntity.setConfirmationKey(tokenGenerator.generateToken());
    accountEntity.setActive(false);

    createAupSignatureForAccountIfNeeded(accountEntity);

    IamRegistrationRequest requestEntity = new IamRegistrationRequest();
    requestEntity.setUuid(UUID.randomUUID().toString());
    requestEntity.setCreationTime(Date.from(clock.instant()));

    requestEntity.setStatus(NEW);
    requestEntity.setNotes(dto.getNotes());

    requestEntity.setAccount(accountEntity);
    accountEntity.setRegistrationRequest(requestEntity);

    if (!isNull(dto.getLabels())) {
      Set<IamLabel> labels =
          dto.getLabels().stream().map(labelConverter::entityFromDto).collect(Collectors.toSet());

      requestEntity.setLabels(labels);
    }

    requestRepository.save(requestEntity);

    eventPublisher.publishEvent(new RegistrationRequestEvent(this, requestEntity,
        "New registration request from user " + accountEntity.getUsername()));

    notificationFactory.createConfirmationMessage(requestEntity);

    return converter.fromEntity(requestEntity);
  }

  @Override
  public List<RegistrationRequestDto> listRequests(IamRegistrationRequestStatus status) {

    List<IamRegistrationRequest> result = new ArrayList<>();

    if (status != null) {
      result = requestRepository.findByStatus(status)
        .orElseThrow(
            () -> new IllegalStateException("No request found with status: " + status.name()));

    } else {
      Sort srt = Sort.by(Sort.Direction.ASC, "creationTime");
      Iterable<IamRegistrationRequest> iter = requestRepository.findAll(srt);
      for (IamRegistrationRequest elem : iter) {
        result.add(elem);
      }
    }

    List<RegistrationRequestDto> requests = new ArrayList<>();

    for (IamRegistrationRequest elem : result) {
      RegistrationRequestDto item = converter.fromEntity(elem);
      requests.add(item);
    }

    return requests;
  }

  @Override
  public List<RegistrationRequestDto> listPendingRequests() {

    List<IamRegistrationRequest> result = requestRepository.findPendingRequests();

    List<RegistrationRequestDto> requests = new ArrayList<>();

    for (IamRegistrationRequest elem : result) {
      RegistrationRequestDto item = converter.fromEntity(elem);
      requests.add(item);
    }

    return requests;
  }


  @Override
  public RegistrationRequestDto confirmRequest(String confirmationKey) {

    IamRegistrationRequest request = requestRepository.findByAccountConfirmationKey(confirmationKey)
      .orElseThrow(() -> new ScimResourceNotFoundException(String
        .format("No registration request found for registration_key [%s]", confirmationKey)));

    return handleConfirm(request);
  }

  @Override
  public Boolean usernameAvailable(String username) {

    Optional<IamAccount> account = iamAccountRepo.findByUsername(username);
    return !account.isPresent();
  }

  @Override
  public Boolean emailAvailable(String emailAddress) {
    return !iamAccountRepo.findByEmail(emailAddress).isPresent();
  }

  private boolean checkStatusTransition(IamRegistrationRequestStatus currentStatus,
      final IamRegistrationRequestStatus newStatus) {

    return allowedStateTransitions.contains(currentStatus, newStatus);
  }



  private RegistrationRequestDto handleApprove(IamRegistrationRequest request) {
    IamAccount account = request.getAccount();
    account.setActive(true);
    account.setResetKey(tokenGenerator.generateToken());
    account.setLastUpdateTime(Date.from(clock.instant()));
    account.setLabels(request.getLabels());

    if (!isNull(lifecycleProperties.getAccount().getAccountLifetimeDays())
        && lifecycleProperties.getAccount().getAccountLifetimeDays() > 0) {
      Instant endTime = clock.instant()
        .plus(lifecycleProperties.getAccount().getAccountLifetimeDays(), ChronoUnit.DAYS);
      account.setEndTime(Date.from(endTime));
    }

    notificationFactory.createAccountActivatedMessage(request);

    request.setStatus(APPROVED);
    request.setLastUpdateTime(Date.from(clock.instant()));
    requestRepository.save(request);

    eventPublisher.publishEvent(new RegistrationApproveEvent(this, request,
        "Approved registration request for user " + account.getUsername()));

    return converter.fromEntity(request);
  }

  private RegistrationRequestDto handleConfirm(IamRegistrationRequest request) {
    request.setStatus(CONFIRMED);
    request.setLastUpdateTime(Date.from(clock.instant()));
    request.getAccount().getUserInfo().setEmailVerified(true);
    request.getAccount().setConfirmationKey(null);
    requestRepository.save(request);

    notificationFactory.createAdminHandleRequestMessage(request);

    eventPublisher.publishEvent(new RegistrationConfirmEvent(this, request, String
      .format("User %s confirmed registration request", request.getAccount().getUsername())));

    return converter.fromEntity(request);
  }

  private RegistrationRequestDto handleReject(IamRegistrationRequest request,
      Optional<String> motivation) {
    request.setStatus(REJECTED);
    notificationFactory.createRequestRejectedMessage(request, motivation);
    RegistrationRequestDto retval = converter.fromEntity(request);

    accountService.deleteAccount(request.getAccount());

    eventPublisher.publishEvent(new RegistrationRejectEvent(this, request,
        "Reject registration request for user " + request.getAccount().getUsername()));

    return retval;
  }

  private void notesSanityChecks(final String notes) {

    if (notes == null) {
      throw new RegistrationRequestValidatorError("Notes field cannot be null");
    }

    if (notes.trim().isEmpty()) {
      throw new RegistrationRequestValidatorError("Notes field cannot be the empty string");
    }
  }

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  @Override
  public RegistrationRequestDto rejectRequest(String requestUuid, Optional<String> motivation) {

    IamRegistrationRequest request = findRequestById(requestUuid);

    if (!checkStatusTransition(request.getStatus(), REJECTED)) {
      throw new IllegalArgumentException(
          String.format("Bad status transition from [%s] to [%s]", request.getStatus(), APPROVED));
    }

    return handleReject(request, motivation);
  }

  @Override
  public RegistrationRequestDto approveRequest(String requestUuid) {

    IamRegistrationRequest request = findRequestById(requestUuid);

    if (!checkStatusTransition(request.getStatus(), APPROVED)) {
      throw new IllegalArgumentException(
          String.format("Bad status transition from [%s] to [%s]", request.getStatus(), APPROVED));
    }

    return handleApprove(request);
  }

  public void setValidationService(RegistrationRequestValidationService validationService) {
    this.validationService = validationService;
  }

  public RegistrationRequestValidationService getValidationService() {
    return validationService;
  }

}
