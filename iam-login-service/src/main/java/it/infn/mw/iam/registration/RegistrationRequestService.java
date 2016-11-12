package it.infn.mw.iam.registration;

import java.util.List;
import java.util.Optional;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;

public interface RegistrationRequestService {

  RegistrationRequestDto createRequest(RegistrationRequestDto request,
      Optional<ExternalAuthenticationRegistrationInfo> extAuthnInfo);

  List<RegistrationRequestDto> listRequests(IamRegistrationRequestStatus status);

  List<RegistrationRequestDto> listPendingRequests();

  RegistrationRequestDto updateStatus(String uuid, IamRegistrationRequestStatus status);

  RegistrationRequestDto confirmRequest(String confirmationKey);

  Boolean usernameAvailable(String username);

  Boolean emailAvailable(String emailAddress);

}
