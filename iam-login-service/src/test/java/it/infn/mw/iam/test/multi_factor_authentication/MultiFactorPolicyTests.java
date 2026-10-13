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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.MandatoryFactorException;
import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorPolicy;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.config.mfa.IamPasskeyProperties;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@ExtendWith(MockitoExtension.class)
class MultiFactorPolicyTests {

  @Mock
  IamTotpMfaService totpMfaService;

  @Mock
  IamPasskeyService passkeyService;

  @Mock
  IamAccountRepository accountRepository;

  IamTotpMfaProperties totpMfaProperties = new IamTotpMfaProperties();
  IamPasskeyProperties passkeyProperties = new IamPasskeyProperties();
  MultiFactorPolicy policy;
  IamAccount account;

  @BeforeEach
  void setup() {
    policy = new MultiFactorPolicy(totpMfaService, totpMfaProperties, passkeyService,
        passkeyProperties, accountRepository);
    account = IamAccount.newAccount();
    account.setId(42L);
    account.setUsername("test");
  }

  @Test
  void mandatoryFollowsBothPolicies() {
    assertThat(policy.isMandatory(), is(false));

    totpMfaProperties.setMultiFactorMandatory(true);
    assertThat(policy.isMandatory(), is(true));

    totpMfaProperties.setMultiFactorMandatory(false);
    passkeyProperties.setMandatory(true);
    when(passkeyService.isEnabled()).thenReturn(false);
    assertThat(policy.isMandatory(), is(false));
    when(passkeyService.isEnabled()).thenReturn(true);
    assertThat(policy.isMandatory(), is(true));
  }

  @Test
  void enrolmentOfAnotherFactorRequiresTheSecondFactorToBeVerified() {
    when(totpMfaService.isAuthenticatorAppActive(account)).thenReturn(true);

    assertThrows(AccessDeniedException.class, () -> policy.checkEnrolmentAllowed(true, account));
    policy.checkEnrolmentAllowed(false, account);
  }

  @Test
  void authenticatorAppIsDisabledWithoutLockWhenNothingIsMandatory() {
    IamTotpMfa disabled = new IamTotpMfa();
    when(totpMfaService.disableTotpMfa(account)).thenReturn(disabled);

    assertThat(policy.disableAuthenticatorApp(account), equalTo(disabled));

    verify(accountRepository, never()).findByIdForUpdate(any());
    verify(passkeyService, never()).isPasskeyActive(any());
  }

  @Test
  void authenticatorAppCannotBeDisabledAsTheLastMandatoryFactor() {
    totpMfaProperties.setMultiFactorMandatory(true);
    when(accountRepository.findByIdForUpdate(42L)).thenReturn(Optional.of(account));
    when(passkeyService.isPasskeyActive(account)).thenReturn(false);

    // The message tells the user what to do: register a passkey, or nothing when the instance
    // has no other factor to offer
    when(passkeyService.isEnabled()).thenReturn(true);
    MandatoryFactorException e = assertThrows(MandatoryFactorException.class,
        () -> policy.disableAuthenticatorApp(account));
    assertThat(e.getMessage(), equalTo(MultiFactorPolicy.LAST_FACTOR_MESSAGE));
    when(passkeyService.isEnabled()).thenReturn(false);
    e = assertThrows(MandatoryFactorException.class, () -> policy.disableAuthenticatorApp(account));
    assertThat(e.getMessage(), equalTo(MultiFactorPolicy.ONLY_FACTOR_MESSAGE));
    verify(totpMfaService, never()).disableTotpMfa(any());

    // With a passkey on the account the authenticator app can go, under the account lock
    when(passkeyService.isPasskeyActive(account)).thenReturn(true);
    policy.disableAuthenticatorApp(account);
    verify(totpMfaService).disableTotpMfa(account);
  }
}
