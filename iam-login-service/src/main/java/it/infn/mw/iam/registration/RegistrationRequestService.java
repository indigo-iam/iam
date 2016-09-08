package it.infn.mw.iam.registration;

import java.util.List;

import it.infn.mw.iam.core.IamRegistrationRequestStatus;

public interface RegistrationRequestService {

  public RegistrationRequestDto createRequest(RegistrationRequestDto request);

  public List<RegistrationRequestDto> listRequests(IamRegistrationRequestStatus status);

  public List<RegistrationRequestDto> listPendingRequests();

  public RegistrationRequestDto updateStatus(String uuid, IamRegistrationRequestStatus status);

  public RegistrationRequestDto confirmRequest(String confirmationKey);

  public Boolean usernameAvailable(String username);

}
