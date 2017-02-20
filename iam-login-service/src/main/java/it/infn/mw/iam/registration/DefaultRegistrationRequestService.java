package it.infn.mw.iam.registration;

import static com.google.common.base.Preconditions.checkNotNull;
import static it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType.OIDC;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.CONFIRMED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.REJECTED;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.google.common.collect.ImmutableTable;
import com.google.common.collect.Table;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.audit.events.RegistrationApproveEvent;
import it.infn.mw.iam.audit.events.RegistrationConfirmEvent;
import it.infn.mw.iam.audit.events.RegistrationRejectEvent;
import it.infn.mw.iam.audit.events.RegistrationRequestEvent;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.notification.NotificationService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;

@Service
public class DefaultRegistrationRequestService
    implements RegistrationRequestService, ApplicationEventPublisherAware {

  @Autowired
  private IamRegistrationRequestRepository requestRepository;

  @Autowired
  private ScimUserProvisioning userService;

  @Autowired
  @Qualifier("defaultNotificationService")
  private NotificationService notificationService;

  @Autowired
  private RegistrationConverter converter;

  @Autowired
  private TokenGenerator tokenGenerator;

  @Autowired
  private IamAccountRepository iamAccountRepo;

  private ApplicationEventPublisher eventPublisher;

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
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
        .build();
      user.addSamlId(samlId);
    }
  }

  @Override
  public RegistrationRequestDto createRequest(RegistrationRequestDto request,
      Optional<ExternalAuthenticationRegistrationInfo> extAuthnInfo) {

    ScimUser.Builder userBuilder = ScimUser.builder()
      .buildName(request.getGivenname(), request.getFamilyname())
      .buildEmail(request.getEmail())
      .userName(request.getUsername())
      .password(request.getPassword());

    extAuthnInfo.ifPresent(i -> addExternalAuthnInfo(userBuilder, i));

    IamAccount newAccount = userService.createAccount(userBuilder.build());
    newAccount.setConfirmationKey(tokenGenerator.generateToken());
    newAccount.setActive(false);

    IamRegistrationRequest regRequest = new IamRegistrationRequest();
    regRequest.setUuid(UUID.randomUUID().toString());
    regRequest.setCreationTime(new Date());

    regRequest.setStatus(NEW);
    regRequest.setNotes(request.getNotes());

    regRequest.setAccount(newAccount);
    newAccount.setRegistrationRequest(regRequest);

    requestRepository.save(regRequest);

    eventPublisher.publishEvent(new RegistrationRequestEvent(this, regRequest,
        "New registration request from user " + newAccount.getUsername()));

    notificationService.createConfirmationMessage(regRequest);

    return converter.fromEntity(regRequest);
  }

  @Override
  public List<RegistrationRequestDto> listRequests(IamRegistrationRequestStatus status) {

    List<IamRegistrationRequest> result = new ArrayList<>();

    if (status != null) {
      result = requestRepository.findByStatus(status).get();
    } else {
      Sort srt = new Sort(Sort.Direction.ASC, "creationTime");
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

    List<IamRegistrationRequest> result = requestRepository.findPendingRequests().get();

    List<RegistrationRequestDto> requests = new ArrayList<>();

    for (IamRegistrationRequest elem : result) {
      RegistrationRequestDto item = converter.fromEntity(elem);
      requests.add(item);
    }

    return requests;
  }

  @Override
  public RegistrationRequestDto updateStatus(String uuid, IamRegistrationRequestStatus status) {

    IamRegistrationRequest request =
        requestRepository.findByUuid(uuid).orElseThrow(() -> new ScimResourceNotFoundException(
            String.format("No request mapped to uuid [%s]", uuid)));

    if (!checkStateTransition(request.getStatus(), status)) {
      throw new IllegalArgumentException(
          String.format("Bad status transition from [%s] to [%s]", request.getStatus(), status));
    }

    RegistrationRequestDto retval = null;

    if (APPROVED.equals(status)) {
      retval = handleApprove(request);

    } else if (CONFIRMED.equals(status)) {
      retval = handleConfirm(request);

    } else if (REJECTED.equals(status)) {
      retval = handleReject(request);
    }

    return retval;
  }

  @Override
  public RegistrationRequestDto confirmRequest(String confirmationKey) {

    IamRegistrationRequest reg = requestRepository.findByAccountConfirmationKey(confirmationKey)
      .orElseThrow(() -> new ScimResourceNotFoundException(String
        .format("No registration request found for registration_key [%s]", confirmationKey)));

    return updateStatus(reg.getUuid(), CONFIRMED);
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

  private boolean checkStateTransition(IamRegistrationRequestStatus currentStatus,
      final IamRegistrationRequestStatus newStatus) {

    return allowedStateTransitions.contains(currentStatus, newStatus);
  }

  private RegistrationRequestDto handleApprove(IamRegistrationRequest request) {
    IamAccount account = request.getAccount();
    account.setActive(true);
    account.setResetKey(tokenGenerator.generateToken());
    account.setLastUpdateTime(new Date());

    notificationService.createAccountActivatedMessage(request);

    request.setStatus(APPROVED);
    request.setLastUpdateTime(new Date());
    requestRepository.save(request);

    eventPublisher.publishEvent(new RegistrationApproveEvent(this, request,
        "Approved registration request for user " + account.getUsername()));

    return converter.fromEntity(request);
  }

  private RegistrationRequestDto handleConfirm(IamRegistrationRequest request) {
    request.getAccount().getUserInfo().setEmailVerified(true);
    request.getAccount().setConfirmationKey(null);

    if (request.getStatus().equals(NEW)) {
      request.setStatus(CONFIRMED);
      notificationService.createAdminHandleRequestMessage(request);
    }

    request.setLastUpdateTime(new Date());
    requestRepository.save(request);

    eventPublisher.publishEvent(new RegistrationConfirmEvent(this, request,
        String.format("User %s confirm registration request", request.getAccount().getUsername())));

    return converter.fromEntity(request);
  }

  private RegistrationRequestDto handleReject(IamRegistrationRequest request) {
    request.setStatus(REJECTED);
    notificationService.createRequestRejectedMessage(request);
    RegistrationRequestDto retval = converter.fromEntity(request);

    userService.delete(request.getAccount().getUuid());

    eventPublisher.publishEvent(new RegistrationRejectEvent(this, request,
        "Reject registration request for user " + request.getAccount().getUsername()));

    return retval;
  }

}
