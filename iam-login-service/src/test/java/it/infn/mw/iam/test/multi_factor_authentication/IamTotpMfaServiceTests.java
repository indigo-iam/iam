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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.secret.SecretGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.DefaultIamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppDisabledEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppEnabledEvent;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@RunWith(MockitoJUnitRunner.class)
public class IamTotpMfaServiceTests extends IamTotpMfaServiceTestSupport {

  private IamTotpMfaService service;

  @Mock
  private IamTotpMfaRepository repository;

  @Mock
  private SecretGenerator secretGenerator;

  @Mock
  private IamAccountService iamAccountService;

  @Mock
  private CodeVerifier codeVerifier;

  @Mock
  private ApplicationEventPublisher eventPublisher;

  @Mock
  private IamTotpMfaProperties iamTotpMfaProperties;

  @Captor
  private ArgumentCaptor<ApplicationEvent> eventCaptor;

  @Before
  public void setup() {
    when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()).thenReturn(KEY_TO_ENCRYPT_DECRYPT);

    when(secretGenerator.generate()).thenReturn("test_secret");
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    when(iamAccountService.saveAccount(TOTP_MFA_ACCOUNT)).thenAnswer(i -> i.getArguments()[0]);
    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(true);

    service = new DefaultIamTotpMfaService(iamAccountService, repository, secretGenerator,
        codeVerifier, eventPublisher, iamTotpMfaProperties);
  }

  @After
  public void tearDown() {
    reset(secretGenerator, repository, iamAccountService, codeVerifier);
  }

  @Test
  public void testAssignsTotpMfaToAccount() {
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = service.addTotpMfaSecret(account);
    verify(repository, times(1)).save(totpMfa);
    verify(secretGenerator, times(1)).generate();

    assertNotNull(totpMfa.getSecret());
    assertFalse(totpMfa.isActive());
    assertThat(totpMfa.getAccount(), equalTo(account));
  }

  @Test(expected = MfaSecretAlreadyBoundException.class)
  public void testAddMfaSecret_whenMfaSecretAssignedFails() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    try {
      service.addTotpMfaSecret(account);
    } catch (MfaSecretAlreadyBoundException e) {
      assertThat(e.getMessage(),
          equalTo("A multi-factor secret is already assigned to this account"));
      throw e;
    }
  }

  @Test
  public void testAddTotpMfaSecret_whenPasswordIsEmpty() {
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());
    when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()).thenReturn("");

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    IamTotpMfaInvalidArgumentError thrownException =
        assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
          // Decrypt the cipherText with empty key
          service.addTotpMfaSecret(account);
        });

    assertTrue(thrownException.getMessage().startsWith("Please ensure that you provide"));
  }

  @Test
  public void testEnablesTotpMfa() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret("secret",
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
    totpMfa.setActive(false);
    totpMfa.setAccount(account);

    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));

    service.enableTotpMfa(account);
    verify(repository, times(1)).save(totpMfa);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AuthenticatorAppEnabledEvent.class));

    AuthenticatorAppEnabledEvent e = (AuthenticatorAppEnabledEvent) event;
    assertTrue(e.getTotpMfa().isActive());
    assertThat(e.getTotpMfa().getAccount(), equalTo(account));
  }

  @Test(expected = TotpMfaAlreadyEnabledException.class)
  public void testEnableTotpMfa_whenTotpMfaEnabledFails() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    try {
      service.enableTotpMfa(account);
    } catch (TotpMfaAlreadyEnabledException e) {
      assertThat(e.getMessage(), equalTo("TOTP MFA is already enabled on this account"));
      throw e;
    }
  }

  @Test(expected = MfaSecretNotFoundException.class)
  public void testEnablesTotpMfa_whenNoMfaSecretAssignedFails() {
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    try {
      service.enableTotpMfa(account);
    } catch (MfaSecretNotFoundException e) {
      assertThat(e.getMessage(), equalTo("No multi-factor secret is attached to this account"));
      throw e;
    }
  }

  @Test
  public void testDisablesTotpMfa() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);

    service.disableTotpMfa(account);
    verify(repository, times(1)).delete(totpMfa);
    verify(iamAccountService, times(1)).saveAccount(account);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AuthenticatorAppDisabledEvent.class));

    AuthenticatorAppDisabledEvent e = (AuthenticatorAppDisabledEvent) event;
    assertThat(e.getTotpMfa().getAccount(), equalTo(account));
  }

  @Test(expected = MfaSecretNotFoundException.class)
  public void testDisablesTotpMfa_whenNoMfaSecretAssignedFails() {
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    try {
      service.disableTotpMfa(account);
    } catch (MfaSecretNotFoundException e) {
      assertThat(e.getMessage(), equalTo("No multi-factor secret is attached to this account"));
      throw e;
    }
  }

  @Test
  public void testVerifyTotp_WithNoMultiFactorSecretAttached() {
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    MfaSecretNotFoundException thrownException =
        assertThrows(MfaSecretNotFoundException.class, () -> {
          service.verifyTotp(account, TOTP_CODE);
        });

    assertTrue(thrownException.getMessage().startsWith("No multi-factor secret is attached"));
  }

  @Test
  public void testVerifyTotp() {
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);

    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    assertTrue(service.verifyTotp(account, TOTP_CODE));
  }

  @Test
  public void testVerifyTotp_WithEmptyPasswordForDecryption() {
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);

    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));
    when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()).thenReturn("");

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    IamTotpMfaInvalidArgumentError thrownException =
        assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
          service.verifyTotp(account, TOTP_CODE);
        });

    assertTrue(thrownException.getMessage().startsWith("Please ensure that you provide"));
  }

  @Test
  public void testVerifyTotp_WithCodeNotValid() {
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);

    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));
    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(false);

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    assertFalse(service.verifyTotp(account, TOTP_CODE));
  }

}
