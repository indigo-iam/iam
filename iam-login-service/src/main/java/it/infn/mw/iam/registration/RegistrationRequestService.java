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

import java.util.List;
import java.util.Optional;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;

public interface RegistrationRequestService {

  RegistrationRequestDto createRequest(RegistrationRequestDto request,
      Optional<ExternalAuthenticationRegistrationInfo> extAuthnInfo);

  List<RegistrationRequestDto> listRequests(IamRegistrationRequestStatus status);

  List<RegistrationRequestDto> listPendingRequests();

  RegistrationRequestDto confirmRequest(String confirmationKey);
  
  RegistrationRequestDto rejectRequest(String requestUuid, Optional<String> motivation, boolean doNotSendEmail);
  
  RegistrationRequestDto approveRequest(String requestUuid);

  Boolean usernameAvailable(String username);

  Boolean emailAvailable(String emailAddress);

}
