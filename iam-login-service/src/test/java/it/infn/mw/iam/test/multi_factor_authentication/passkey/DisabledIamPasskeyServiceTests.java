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
package it.infn.mw.iam.test.multi_factor_authentication.passkey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DisabledIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyDisabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;

@ExtendWith(MockitoExtension.class)
class DisabledIamPasskeyServiceTests {

  @Mock
  IamPasskeyRepository passkeyRepository;

  private DisabledIamPasskeyService service;
  private final IamAccount account = IamAccount.newAccount();

  @BeforeEach
  void setup() {
    service = new DisabledIamPasskeyService(passkeyRepository);
  }

  @Test
  void disabledServiceReportsNoPasskeys() {
    assertThat(service.isEnabled(), is(false));
    assertThat(service.isPasskeyActive(account), is(false));
    assertThat(service.getPasskeys(account), empty());
    assertThat(service.removeAllPasskeys(account), empty());
  }

  @Test
  void disabledServiceStillRemovesStoredPasskeys() {
    IamPasskey stored = new IamPasskey();
    when(passkeyRepository.findByAccountId(any())).thenReturn(List.of(stored));

    assertThat(service.removeAllPasskeys(account), contains(stored));
    verify(passkeyRepository).deleteAll(List.of(stored));
  }

  @Test
  void disabledServiceRejectsCeremonies() {
    assertThrows(PasskeyDisabledException.class,
        () -> service.createChallenge(account, Purpose.REGISTRATION));
    assertThrows(PasskeyDisabledException.class,
        () -> service.getRegistrationOptions(account, null));
    assertThrows(PasskeyDisabledException.class,
        () -> service.registerPasskey(account, null, null));
    assertThrows(PasskeyDisabledException.class,
        () -> service.getAuthenticationOptions(account, null));
    assertThrows(PasskeyDisabledException.class,
        () -> service.verifyPasskey(account, null, null));
    assertThrows(PasskeyDisabledException.class, () -> service.removePasskey(account, "uuid"));
  }
}
