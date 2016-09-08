package it.infn.mw.iam.registration;

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
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.notification.NotificationService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;

@Service
public class DefaultRegistrationRequestService implements RegistrationRequestService {

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

  private static Table<IamRegistrationRequestStatus, IamRegistrationRequestStatus, Boolean> transictions;

  {
    transictions = HashBasedTable.create();
    transictions.put(NEW, CONFIRMED, true);
    transictions.put(NEW, APPROVED, true);
    transictions.put(NEW, REJECTED, true);
    transictions.put(CONFIRMED, APPROVED, true);
    transictions.put(CONFIRMED, REJECTED, true);
    transictions.put(APPROVED, CONFIRMED, true);
    transictions.put(REJECTED, CONFIRMED, true);
  }

  @Override
  public RegistrationRequestDto createRequest(RegistrationRequestDto request) {

    ScimUser user = ScimUser.builder()
      .buildName(request.getGivenname(), request.getFamilyname())
      .buildEmail(request.getEmail())
      .userName(request.getUsername())
      .build();

    IamAccount newAccount = userService.createAccount(user);
    newAccount.setConfirmationKey(tokenGenerator.generateToken());
    newAccount.setActive(false);

    IamRegistrationRequest regRequest = new IamRegistrationRequest();
    regRequest.setUuid(UUID.randomUUID().toString());
    regRequest.setCreationTime(new Date());
    regRequest.setAccount(newAccount);
    regRequest.setStatus(NEW);
    regRequest.setNotes(request.getNotes());

    requestRepository.save(regRequest);

    IamEmailNotification notification = notificationService.createConfirmationMessage(regRequest);
    List<IamEmailNotification> notificationList = new ArrayList<>();
    notificationList.add(notification);
    regRequest.setNotifications(notificationList);

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

    IamRegistrationRequest reg =
        requestRepository.findByUuid(uuid).orElseThrow(() -> new ScimResourceNotFoundException(
            String.format("No request mapped to uuid [%s]", uuid)));

    if (!checkStateTransiction(reg.getStatus(), status)) {
      throw new IllegalArgumentException(
          String.format("Bad status transition from [%s] to [%s]", reg.getStatus(), status));
    }

    if (APPROVED.equals(status)) {
      IamAccount account = reg.getAccount();
      account.setActive(true);
      account.setResetKey(tokenGenerator.generateToken());
      account.setLastUpdateTime(new Date());
      notificationService.createAccountActivatedMessage(reg);
      reg.setStatus(status);

    } else if (CONFIRMED.equals(status)) {
      reg.getAccount().getUserInfo().setEmailVerified(true);
      reg.getAccount().setConfirmationKey(null);

      if (reg.getStatus().equals(NEW)) {
        reg.setStatus(status);
        notificationService.createAdminHandleRequestMessage(reg);
      }

    } else if (REJECTED.equals(status)) {
      reg.setStatus(status);
      notificationService.createRequestRejectedMessage(reg);
    }

    reg.setLastUpdateTime(new Date());
    requestRepository.save(reg);

    return converter.fromEntity(reg);
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

  private boolean checkStateTransiction(IamRegistrationRequestStatus currentStatus,
      final IamRegistrationRequestStatus newStatus) {

    return transictions.contains(currentStatus, newStatus);
  }

}
