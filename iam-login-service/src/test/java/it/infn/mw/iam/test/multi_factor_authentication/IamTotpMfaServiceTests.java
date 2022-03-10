package it.infn.mw.iam.test.multi_factor_authentication;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

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
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import it.infn.mw.iam.api.account.multi_factor_authentication.DefaultIamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppDisabledEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.AuthenticatorAppEnabledEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.MfaSecretAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.core.user.exception.TotpMfaAlreadyEnabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@RunWith(MockitoJUnitRunner.class)
public class IamTotpMfaServiceTests extends IamTotpMfaServiceTestSupport {

  private IamTotpMfaService service;

  @Mock
  private IamTotpMfaRepository repository;

  @Mock
  private SecretGenerator secretGenerator;

  @Mock
  private RecoveryCodeGenerator recoveryCodeGenerator;

  @Mock
  private IamAccountService iamAccountService;

  @Mock
  private CodeVerifier codeVerifier;

  @Mock
  private ApplicationEventPublisher eventPublisher;

  @Captor
  private ArgumentCaptor<ApplicationEvent> eventCaptor;

  @Before
  public void setup() {
    when(secretGenerator.generate()).thenReturn("test_secret");
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.of(TOTP_MFA));
    when(iamAccountService.saveAccount(TOTP_MFA_ACCOUNT)).thenAnswer(i -> i.getArguments()[0]);
    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(true);

    String[] testArray = {TOTP_RECOVERY_CODE_STRING_7, TOTP_RECOVERY_CODE_STRING_8,
        TOTP_RECOVERY_CODE_STRING_9, TOTP_RECOVERY_CODE_STRING_10, TOTP_RECOVERY_CODE_STRING_11,
        TOTP_RECOVERY_CODE_STRING_12};
    when(recoveryCodeGenerator.generateCodes(anyInt())).thenReturn(testArray);

    service = new DefaultIamTotpMfaService(iamAccountService, repository, secretGenerator,
        recoveryCodeGenerator, codeVerifier, eventPublisher);
  }

  @After
  public void tearDown() {
    reset(secretGenerator, repository, iamAccountService, codeVerifier, recoveryCodeGenerator);
  }

  @Test
  public void testAssignsTotpMfaToAccount() {
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = service.addTotpMfaSecret(account);
    verify(repository, times(1)).save(totpMfa);
    verify(secretGenerator, times(1)).generate();
    verify(recoveryCodeGenerator, times(1)).generateCodes(anyInt());

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
  public void testAddsMfaRecoveryCodesToAccount() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    Set<IamTotpRecoveryCode> originalCodes = totpMfa.getRecoveryCodes();

    try {
      totpMfa = service.addTotpMfaRecoveryCodes(account);
    } catch (MfaSecretNotFoundException e) {
      assertThat(e.getMessage(), equalTo("No multi-factor secret is attached to this account"));
      throw e;
    }

    Set<IamTotpRecoveryCode> newCodes = totpMfa.getRecoveryCodes();
    assertThat(originalCodes.toArray(), not(equalTo(newCodes.toArray())));
  }

  @Test(expected = MfaSecretNotFoundException.class)
  public void testAddsMfaRecoveryCode_whenNoMfaSecretAssignedFails() {
    when(repository.findByAccount(TOTP_MFA_ACCOUNT)).thenReturn(Optional.empty());

    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);

    try {
      service.addTotpMfaRecoveryCodes(account);
    } catch (MfaSecretNotFoundException e) {
      assertThat(e.getMessage(), equalTo("No multi-factor secret is attached to this account"));
      throw e;
    }
  }

  @Test
  public void testEnablesTotpMfa() {
    IamAccount account = cloneAccount(TOTP_MFA_ACCOUNT);
    IamTotpMfa totpMfa = cloneTotpMfa(TOTP_MFA);
    totpMfa.setSecret("secret");
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
}
