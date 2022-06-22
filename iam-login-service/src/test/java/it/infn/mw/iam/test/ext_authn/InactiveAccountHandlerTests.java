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
package it.infn.mw.iam.test.ext_authn;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.DisabledException;

import it.infn.mw.iam.authn.DefaultInactiveAccountAuthenticationHandler;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;


public class InactiveAccountHandlerTests {
  
  public static final String ORG_NAME = "indigo-dc";
  
  @Test
  public void inactiveAccountHandlerSilentlyIgnoresActiveAccount() {

    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(true);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(ORG_NAME);

    handler.handleInactiveAccount(account);

  }

  @Test
  public void inactiveAccountHandlerRaiseErrorForDisabledUser() {

    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(ORG_NAME);

    try {

      handler.handleInactiveAccount(account);
      fail("Expected exception not raised");

    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), equalTo("Your account is suspended"));

    }
  }

  @Test
  public void inactiveAccountHandlerInformsOfRegistrationRequestWaitingConfirmation() {
    IamRegistrationRequest req = Mockito.mock(IamRegistrationRequest.class);
    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    Mockito.when(account.getRegistrationRequest()).thenReturn(req);
    Mockito.when(req.getStatus()).thenReturn(IamRegistrationRequestStatus.NEW);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(ORG_NAME);

    try {

      handler.handleInactiveAccount(account);


    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), containsString("confirmation URL"));

    }
  }

  @Test
  public void inactiveAccountHandlerInformsOfRegistrationRequestWaitingForApproval() {
    IamRegistrationRequest req = Mockito.mock(IamRegistrationRequest.class);
    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    Mockito.when(account.getRegistrationRequest()).thenReturn(req);
    Mockito.when(req.getStatus()).thenReturn(IamRegistrationRequestStatus.CONFIRMED);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(ORG_NAME);

    try {

      handler.handleInactiveAccount(account);


    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), containsString("administrator approval"));

    }
  }

  @Test
  public void inactiveAccountHandlerIgnoresApprovedRegistrationRequest() {
    IamRegistrationRequest req = Mockito.mock(IamRegistrationRequest.class);
    IamAccount account = Mockito.mock(IamAccount.class);

    Mockito.when(account.isActive()).thenReturn(false);
    Mockito.when(account.getRegistrationRequest()).thenReturn(req);
    Mockito.when(req.getStatus()).thenReturn(IamRegistrationRequestStatus.APPROVED);

    DefaultInactiveAccountAuthenticationHandler handler =
        new DefaultInactiveAccountAuthenticationHandler(ORG_NAME);

    try {

      handler.handleInactiveAccount(account);


    } catch (DisabledException ex) {
      assertThat(ex.getMessage(), equalTo("Your account is suspended"));

    }
  }
}
