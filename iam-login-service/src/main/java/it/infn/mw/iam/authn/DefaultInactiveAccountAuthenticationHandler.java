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
package it.infn.mw.iam.authn;

import static it.infn.mw.iam.core.IamRegistrationRequestStatus.CONFIRMED;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW;

import java.util.EnumSet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class DefaultInactiveAccountAuthenticationHandler
    implements InactiveAccountAuthenticationHander {

  public static final String ACCOUNT_SUSPENDED_MESSAGE = "Your account is suspended";

  EnumSet<IamRegistrationRequestStatus> ongoingStatus = EnumSet.of(NEW, CONFIRMED);

  public final String waitingConfirmationMsg;
  public final String waitingApprovalMsg;

  @Autowired
  public DefaultInactiveAccountAuthenticationHandler(
      @Value("${iam.organisation.name}") String organisationName) {


    waitingConfirmationMsg = String.format("Your registration request to %s was submitted "
        + "successfully, but you haven't confirmed it yet. Check your inbox, you should have received a message with "
        + "a confirmation URL", organisationName);

    waitingApprovalMsg = String
      .format("Your registration request to %s was submitted and confirmed successfully, "
          + "and is now waiting for administrator approval. As soon as your request is approved you will receive a "
          + "confirmation email", organisationName);
  }

  protected boolean hasOngoingRegistrationRequest(IamAccount account) {

    return (account.getRegistrationRequest() != null
        && ongoingStatus.contains(account.getRegistrationRequest().getStatus()));

  }

  protected boolean requestWaitingForUserConfirmation(IamAccount account) {
    if (account.getRegistrationRequest() != null) {
      return (NEW.equals(account.getRegistrationRequest().getStatus()));
    }
    return false;
  }

  protected boolean requestWaitingForAdminApproval(IamAccount account) {
    if (account.getRegistrationRequest() != null) {
      return (CONFIRMED.equals(account.getRegistrationRequest().getStatus()));
    }
    return false;
  }

  protected void raiseAuthenticationError(String msg) {
    throw new DisabledException(msg);
  }

  @Override
  public void handleInactiveAccount(IamAccount account) throws UsernameNotFoundException {

    if (account.isActive()) {
      return;
    }

    if (hasOngoingRegistrationRequest(account)) {

      if (requestWaitingForUserConfirmation(account)) {
        raiseAuthenticationError(waitingConfirmationMsg);
      }

      if (requestWaitingForAdminApproval(account)) {
        raiseAuthenticationError(waitingApprovalMsg);
      }
    }

    raiseAuthenticationError(ACCOUNT_SUSPENDED_MESSAGE);
  }

}
