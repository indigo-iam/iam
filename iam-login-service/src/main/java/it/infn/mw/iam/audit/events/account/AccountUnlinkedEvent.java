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
package it.infn.mw.iam.audit.events.account;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountUnlinkedEvent extends AccountEvent {

  private static final long serialVersionUID = -1605221918249294636L;

  @JsonIgnoreProperties({"email", "GIVEN_NAME", "familyName", "issuer", "subject"})
  private final ExternalAuthenticationType externalAuthenticationType;
  
  private final String issuer;
  private final String subject;

  public AccountUnlinkedEvent(Object source, IamAccount account,
      ExternalAuthenticationType accountType, String issuer, String subject, String message) {
    super(source, account, message);
    this.externalAuthenticationType = accountType;
    this.issuer = issuer;
    this.subject = subject;
  }

  public ExternalAuthenticationType getExternalAuthenticationType() {
    return externalAuthenticationType;
  }

  public String getIssuer() {
    return issuer;
  }

  public String getSubject() {
    return subject;
  }

}
