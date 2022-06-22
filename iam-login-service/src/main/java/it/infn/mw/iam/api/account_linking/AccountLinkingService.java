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
package it.infn.mw.iam.api.account_linking;

import java.security.Principal;
import java.util.Date;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;

public interface AccountLinkingService {

  void linkX509ProxyCertificate(Principal authenticatedUser, 
      IamX509AuthenticationCredential x509Credential, String proxyCertificatePemString,
      Date proxyCertificateExpirationTime);
  
  void linkX509Certificate(Principal authenticatedUser,
      IamX509AuthenticationCredential x509Credential);

  void unlinkX509Certificate(Principal authenticatedUser, String certificateSubject);

  void linkExternalAccount(Principal authenticatedUser,
      AbstractExternalAuthenticationToken<?> externalAuthenticationToken);

  void unlinkExternalAccount(Principal authenticatedUser, ExternalAuthenticationType type,
      String iss, String sub, String attributeId);

}
