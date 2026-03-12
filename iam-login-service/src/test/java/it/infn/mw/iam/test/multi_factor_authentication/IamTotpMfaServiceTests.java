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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.DefaultIamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppDisabledEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppEnabledEvent;
import it.infn.mw.iam.config.IamProperties;
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

@ExtendWith(MockitoExtension.class)
class IamTotpMfaServiceTests extends IamTotpMfaServiceTestSupport {

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
  
  @Mock
  private QrGenerator qrGenerator;

  @Mock
  private IamProperties iamProperties;

  @Mock
  private IamProperties.Organisation organisation;

  @Captor
  private ArgumentCaptor<ApplicationEvent> eventCaptor;

  @BeforeEach
  void setup() {
    lenient().when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt())
      .thenReturn(KEY_TO_ENCRYPT_DECRYPT);

    lenient().when(secretGenerator.generate()).thenReturn("test_secret");
    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    lenient().when(iamAccountService.saveAccount(TOTP_MFA_ACCOUNT))
      .thenAnswer(i -> i.getArguments()[0]);
    lenient().when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(true);

    service = new DefaultIamTotpMfaService(iamAccountService, repository, secretGenerator,
        codeVerifier, eventPublisher, iamTotpMfaProperties, qrGenerator, iamProperties);
  }

  @AfterEach
  void tearDown() {
    reset(secretGenerator, repository, iamAccountService, codeVerifier);
  }

  @Test
  void testAssignsTotpMfaToAccount() {
    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = service.addTotpMfaSecret(account);
    verify(repository, times(1)).save(totpMfa);
    verify(secretGenerator, times(1)).generate();

    assertNotNull(totpMfa.getSecret());
    assertFalse(totpMfa.isActive());
    assertThat(totpMfa.getAccount(), equalTo(account));
  }

  @Test
  void testAddMfaSecretWhenMfaSecretAssignedFails() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    MfaSecretAlreadyBoundException e =
        assertThrows(MfaSecretAlreadyBoundException.class, () -> service.addTotpMfaSecret(account));
    assertThat(e.getMessage(),
        equalTo("A multi-factor secret is already assigned to this account"));
  }

  @Test
  void testAddMfaSecretWhenTotpIsNotActive() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    TOTP_MFA.setActive(false);
    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    IamTotpMfa totpMfa = service.addTotpMfaSecret(account);
    assertFalse(totpMfa.isActive());
  }

  @Test
  void testAddTotpMfaSecretWhenPasswordIsEmpty() {
    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());
    lenient().when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()).thenReturn("");

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    IamTotpMfaInvalidArgumentError e = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
      service.addTotpMfaSecret(account);
    });

    assertTrue(e.getMessage().startsWith("Please ensure that you provide"));
  }

  @Test
  void testEnablesTotpMfa() throws Exception {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret("secret",
        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
    totpMfa.setActive(false);
    totpMfa.setAccount(account);

    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));

    service.enableTotpMfa(account);
    verify(repository, times(1)).save(totpMfa);
    verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AuthenticatorAppEnabledEvent.class));

    AuthenticatorAppEnabledEvent e = (AuthenticatorAppEnabledEvent) event;
    assertTrue(e.getTotpMfa().isActive());
    assertThat(e.getTotpMfa().getAccount(), equalTo(account));
  }

  @Test
  void testEnableTotpMfaWhenTotpMfaEnabledFails() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    TotpMfaAlreadyEnabledException e =
        assertThrows(TotpMfaAlreadyEnabledException.class, () -> service.enableTotpMfa(account));
    assertThat(e.getMessage(), equalTo("TOTP MFA is already enabled on this account"));
  }

  @Test
  void testEnablesTotpMfaWhenNoMfaSecretAssignedFails() {
    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    MfaSecretNotFoundException e =
        assertThrows(MfaSecretNotFoundException.class, () -> service.enableTotpMfa(account));
    assertThat(e.getMessage(), equalTo("No multi-factor secret is attached to this account"));
  }

  @Test
  void testDisablesTotpMfa() {
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

  @Test
  void testDisablesTotpMfaWhenNoMfaSecretAssignedFails() {
    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    MfaSecretNotFoundException e =
        assertThrows(MfaSecretNotFoundException.class, () -> service.disableTotpMfa(account));
    assertThat(e.getMessage(), equalTo("No multi-factor secret is attached to this account"));
  }

  @Test
  void testVerifyTotpWithNoMultiFactorSecretAttached() {
    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    MfaSecretNotFoundException thrownException =
        assertThrows(MfaSecretNotFoundException.class, () -> {
          service.verifyTotp(account, TOTP_CODE);
        });

    assertTrue(thrownException.getMessage().startsWith("No multi-factor secret is attached"));
  }

  @Test
  void testVerifyTotp() {
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);

    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    assertTrue(service.verifyTotp(account, TOTP_CODE));
  }

  @Test
  void testVerifyTotpWithEmptyPasswordForDecryption() {
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);

    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));
    lenient().when(iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()).thenReturn("");

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    IamTotpMfaInvalidArgumentError thrownException =
        assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
          service.verifyTotp(account, TOTP_CODE);
        });

    assertTrue(thrownException.getMessage().startsWith("Please ensure that you provide"));
  }

  @Test
  void testVerifyTotpWithCodeNotValid() {
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);

    lenient().when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(totpMfa));
    lenient().when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(false);

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    assertFalse(service.verifyTotp(account, TOTP_CODE));
  }

  @Test
  void generateQRCodeFromSecretSuccess() throws Exception {
    
    String secret = "JBSWY3DPEHPK3PXP";
    String username = "alice@example.com";
    byte[] pngBytes = "PNG_IMAGE_BYTES".getBytes(StandardCharsets.UTF_8);
    when(qrGenerator.generate(any(QrData.class))).thenReturn(pngBytes);
    when(qrGenerator.getImageMimeType()).thenReturn("image/png");
    when(iamProperties.getOrganisation()).thenReturn(organisation);
    when(organisation.getName()).thenReturn("Test Corp");

    
    String dataUri = service.generateQRCodeFromSecret(secret, username);

    ArgumentCaptor<QrData> dataCaptor = ArgumentCaptor.forClass(QrData.class);
    verify(qrGenerator).generate(dataCaptor.capture());
    QrData built = dataCaptor.getValue();

    
    assertThat(built.getLabel()).isEqualTo(username);
    assertThat(built.getSecret()).isEqualTo(secret);
    assertThat(built.getIssuer()).isEqualTo("INDIGO IAM" + " - " + "Test Corp");
    assertThat(built.getAlgorithm()).isEqualTo("SHA1");
    assertThat(built.getDigits()).isEqualTo(6);
    assertThat(built.getPeriod()).isEqualTo(30);

    assertThat(dataUri).startsWith("data:image/png;base64,");
    String base64Part = dataUri.substring("data:image/png;base64,".length());
    assertThat(Base64.getDecoder().decode(base64Part)).isEqualTo(pngBytes);

    verify(qrGenerator, times(1)).generate(any(QrData.class));
    verify(qrGenerator, times(1)).getImageMimeType();
  }

}
