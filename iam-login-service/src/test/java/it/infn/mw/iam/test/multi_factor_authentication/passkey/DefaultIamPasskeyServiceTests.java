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

import static it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.base64Url;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.sql.SQLIntegrityConstraintViolationException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.jpa.JpaSystemException;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionOptionsDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationOptionsDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRelyingParty;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyCeremonyException;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyLimitExceededException;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyNotFoundException;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.PasskeyRegisteredEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.PasskeyRemovedEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.PasskeyVerifiedEvent;
import it.infn.mw.iam.config.mfa.IamPasskeyProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;

@ExtendWith(MockitoExtension.class)
class DefaultIamPasskeyServiceTests extends PasskeyTestSupport {

  private static final String TEST_USERNAME = "test-user";
  private static final String TEST_UUID = "a23deabf-88a7-47af-84b5-1d535a1b267c";
  private static final String OTHER_USERNAME = "other-user";
  private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

  @Mock
  IamPasskeyRepository passkeyRepository;

  @Mock
  IamAccountRepository accountRepository;

  @Mock
  IamAccountService accountService;

  @Mock
  NotificationFactory notificationFactory;

  @Mock
  ApplicationEventPublisher eventPublisher;

  IamPasskeyProperties properties;
  PasskeyRelyingParty relyingParty;
  Clock clock;
  DefaultIamPasskeyService service;
  IamAccount account;

  @BeforeEach
  void setup() {
    clock = Clock.fixed(NOW, ZoneId.of("UTC"));
    properties = new IamPasskeyProperties();
    properties.setEnabled(true);
    properties.setMaxCredentialsPerAccount(2);
    properties.setChallengeTimeoutSeconds(60);
    relyingParty = new PasskeyRelyingParty(Set.of(TEST_ORIGIN), TEST_RP_ID, TEST_RP_NAME, false);
    service = new DefaultIamPasskeyService(clock, properties, relyingParty, passkeyRepository,
        accountRepository, accountService, notificationFactory, eventPublisher);

    account = IamAccount.newAccount();
    account.setId(42L);
    account.setUuid(TEST_UUID);
    account.setUsername(TEST_USERNAME);
    account.getUserInfo().setGivenName("Test");
    account.getUserInfo().setFamilyName("User");
    account.getUserInfo().setEmail("test@example.org");

    lenient().when(passkeyRepository.save(any(IamPasskey.class)))
      .thenAnswer(i -> i.getArgument(0));
    lenient().when(passkeyRepository.saveAndFlush(any(IamPasskey.class)))
      .thenAnswer(i -> i.getArgument(0));
    lenient().when(accountRepository.findByIdForUpdate(42L)).thenReturn(Optional.of(account));
  }

  private IamPasskey registeredPasskey(PasskeyTestAuthenticator authenticator) {
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L);
    when(passkeyRepository.findByCredentialId(anyString())).thenReturn(Optional.empty());
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    return service.registerPasskey(account, challenge, registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of("usb")));
  }

  @Test
  void serviceIsEnabled() {
    assertThat(service.isEnabled(), is(true));
  }

  @Test
  void isPasskeyActiveReflectsRegisteredCredentials() {
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L, 1L);
    assertThat(service.isPasskeyActive(account), is(false));
    assertThat(service.isPasskeyActive(account), is(true));
  }

  @Test
  void challengeIsBoundToPurposeUserAndExpiry() {
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);

    assertThat(challenge.getValue().length, equalTo(DefaultIamPasskeyService.CHALLENGE_SIZE));
    assertThat(challenge.matches(Purpose.REGISTRATION, TEST_USERNAME), is(true));
    assertThat(challenge.matches(Purpose.AUTHENTICATION, TEST_USERNAME), is(false));
    assertThat(challenge.matches(Purpose.REGISTRATION, OTHER_USERNAME), is(false));
    assertThat(challenge.getExpiresAt(), equalTo(NOW.plusSeconds(60)));
    assertThat(challenge.isExpired(NOW.plusSeconds(59)), is(false));
    assertThat(challenge.isExpired(NOW.plusSeconds(60)), is(true));

    PasskeyChallenge other = service.createChallenge(account, Purpose.REGISTRATION);
    assertThat(base64Url(other.getValue()), not(base64Url(challenge.getValue())));
  }

  @Test
  void registrationOptionsDescribeRelyingPartyUserAndExistingCredentials() {
    IamPasskey existing = new IamPasskey(NOW, account);
    existing.setCredentialId("existing-id");
    existing.setTransports("usb,nfc");
    when(passkeyRepository.findByAccountId(42L)).thenReturn(List.of(existing));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);

    PasskeyRegistrationOptionsDTO options = service.getRegistrationOptions(account, challenge);

    assertThat(options.getRp().getId(), equalTo(TEST_RP_ID));
    assertThat(options.getRp().getName(), equalTo(TEST_RP_NAME));
    assertThat(options.getUser().getName(), equalTo(TEST_USERNAME));
    assertThat(options.getUser().getDisplayName(), equalTo("Test User"));
    assertThat(options.getUser().getId(),
        equalTo(base64Url(TEST_UUID.getBytes(StandardCharsets.UTF_8))));
    assertThat(options.getChallenge(), equalTo(base64Url(challenge.getValue())));
    assertThat(options.getPubKeyCredParams(), hasSize(3));
    assertThat(options.getPubKeyCredParams().get(0).getAlg(), equalTo(-7L));
    assertThat(options.getPubKeyCredParams().get(1).getAlg(), equalTo(-8L));
    assertThat(options.getPubKeyCredParams().get(2).getAlg(), equalTo(-257L));
    // The browser gets 30 s less than the 60 s challenge lifetime configured in setup()
    assertThat(options.getTimeout(), equalTo(30000L));
    assertThat(options.getExcludeCredentials(), hasSize(1));
    assertThat(options.getExcludeCredentials().get(0).getId(), equalTo("existing-id"));
    assertThat(options.getExcludeCredentials().get(0).getTransports(), equalTo(List.of("usb", "nfc")));
    assertThat(options.getAuthenticatorSelection().getUserVerification(), equalTo("preferred"));
    assertThat(options.getAuthenticatorSelection().getResidentKey(), equalTo("discouraged"));
    assertThat(options.getAttestation(), equalTo("none"));
  }

  @Test
  void registrationOptionsRejectAuthenticationChallenge() {
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.getRegistrationOptions(account, challenge));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.CHALLENGE_MISMATCH_MESSAGE));
  }

  @Test
  void registrationPersistsCredentialAndNotifies() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    IamPasskey passkey = registeredPasskey(authenticator);

    assertThat(passkey.getUuid(), notNullValue());
    assertThat(passkey.getAccount(), equalTo(account));
    assertThat(passkey.getLabel(), equalTo(TEST_LABEL));
    assertThat(passkey.getCredentialId(), equalTo(authenticator.getCredentialIdBase64Url()));
    assertThat(passkey.getAttestedCredentialData(), notNullValue());
    assertThat(passkey.getAaguid(), equalTo(authenticator.getAaguid().toString()));
    assertThat(passkey.getSignCount(), equalTo(0L));
    assertThat(passkey.getTransports(), equalTo("usb"));
    assertThat(passkey.getCreationTime().toInstant(), equalTo(NOW));
    assertThat(passkey.getLastUsedTime(), nullValue());

    verify(accountRepository).findByIdForUpdate(42L);
    verify(passkeyRepository).saveAndFlush(passkey);
    verify(accountService).saveAccount(account);
    verify(notificationFactory).createPasskeyRegisteredMessage(account, passkey);
    ArgumentCaptor<ApplicationEvent> event = ArgumentCaptor.forClass(ApplicationEvent.class);
    verify(eventPublisher).publishEvent(event.capture());
    assertThat(event.getValue(), instanceOf(PasskeyRegisteredEvent.class));
  }

  @Test
  void registrationTrimsLabel() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L);
    when(passkeyRepository.findByCredentialId(anyString())).thenReturn(Optional.empty());
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);

    IamPasskey passkey = service.registerPasskey(account, challenge, registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of(), "  my key  "));

    assertThat(passkey.getLabel(), equalTo("my key"));
  }

  @Test
  void registrationWithoutChallengeFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyRegistrationDTO registration =
        registrationFor(authenticator, base64Url(new byte[32]), TEST_ORIGIN, false, List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, null, registration));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.CHALLENGE_MISSING_MESSAGE));
    verify(passkeyRepository, never()).saveAndFlush(any());
    verify(accountRepository, never()).findByIdForUpdate(any());
  }

  @Test
  void registrationWithExpiredChallengeFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyChallenge challenge = new PasskeyChallenge(new byte[32], Purpose.REGISTRATION,
        TEST_USERNAME, NOW.minusSeconds(1));
    PasskeyRegistrationDTO registration =
        registrationFor(authenticator, base64Url(challenge.getValue()), TEST_ORIGIN, false,
            List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, challenge, registration));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.CHALLENGE_EXPIRED_MESSAGE));
  }

  @Test
  void registrationWithChallengeOfAnotherUserFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyChallenge challenge = new PasskeyChallenge(new byte[32], Purpose.REGISTRATION,
        OTHER_USERNAME, NOW.plusSeconds(60));
    PasskeyRegistrationDTO registration =
        registrationFor(authenticator, base64Url(challenge.getValue()), TEST_ORIGIN, false,
            List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, challenge, registration));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.CHALLENGE_MISMATCH_MESSAGE));
  }

  @Test
  void registrationBeyondLimitFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.countByAccountId(42L)).thenReturn(2L);
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of());

    assertThrows(PasskeyLimitExceededException.class,
        () -> service.registerPasskey(account, challenge, registration));
    verify(passkeyRepository, never()).saveAndFlush(any());
  }

  @Test
  void registrationOfAlreadyRegisteredCredentialFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L);
    when(passkeyRepository.findByCredentialId(authenticator.getCredentialIdBase64Url()))
      .thenReturn(Optional.of(new IamPasskey(NOW, account)));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, challenge, registration));
    assertThat(e.getMessage(),
        equalTo(DefaultIamPasskeyService.CREDENTIAL_ALREADY_REGISTERED_MESSAGE));
    verify(passkeyRepository, never()).saveAndFlush(any());
  }

  @Test
  void concurrentRegistrationOfSameCredentialIsTranslated() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L);
    when(passkeyRepository.findByCredentialId(anyString())).thenReturn(Optional.empty());
    when(passkeyRepository.saveAndFlush(any(IamPasskey.class)))
      .thenThrow(new DataIntegrityViolationException("duplicate"));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, challenge, registration));
    assertThat(e.getMessage(),
        equalTo(DefaultIamPasskeyService.CREDENTIAL_ALREADY_REGISTERED_MESSAGE));
    verify(notificationFactory, never()).createPasskeyRegisteredMessage(any(), any());
  }

  @Test
  void constraintViolationReportedByEclipseLinkIsTranslated() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L);
    when(passkeyRepository.findByCredentialId(anyString())).thenReturn(Optional.empty());
    // EclipseLink surfaces unique constraint violations as JpaSystemException wrapping the
    // SQLIntegrityConstraintViolationException raised by the driver
    when(passkeyRepository.saveAndFlush(any(IamPasskey.class))).thenThrow(new JpaSystemException(
        new RuntimeException(new SQLIntegrityConstraintViolationException("duplicate"))));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, challenge, registration));
    assertThat(e.getMessage(),
        equalTo(DefaultIamPasskeyService.CREDENTIAL_ALREADY_REGISTERED_MESSAGE));
    verify(notificationFactory, never()).createPasskeyRegisteredMessage(any(), any());
  }

  @Test
  void otherDataAccessErrorsAreNotTranslated() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L);
    when(passkeyRepository.findByCredentialId(anyString())).thenReturn(Optional.empty());
    when(passkeyRepository.saveAndFlush(any(IamPasskey.class)))
      .thenThrow(new JpaSystemException(new RuntimeException("connection lost")));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of());

    assertThrows(JpaSystemException.class,
        () -> service.registerPasskey(account, challenge, registration));
  }

  @Test
  void registrationForUnknownAccountFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(accountRepository.findByIdForUpdate(42L)).thenReturn(Optional.empty());
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        base64Url(challenge.getValue()), TEST_ORIGIN, false, List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, challenge, registration));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.UNKNOWN_ACCOUNT_MESSAGE));
  }

  @Test
  void registrationWithInvalidAttestationFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.countByAccountId(42L)).thenReturn(0L);
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        base64Url(new byte[32]), TEST_ORIGIN, false, List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.registerPasskey(account, challenge, registration));
    assertThat(e.getMessage(), containsString("registration failed"));
    verify(passkeyRepository, never()).saveAndFlush(any());
  }

  @Test
  void authenticationOptionsListAccountCredentials() {
    IamPasskey existing = new IamPasskey(NOW, account);
    existing.setCredentialId("existing-id");
    when(passkeyRepository.findByAccountId(42L)).thenReturn(List.of(existing));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);

    PasskeyAssertionOptionsDTO options = service.getAuthenticationOptions(account, challenge);

    assertThat(options.getChallenge(), equalTo(base64Url(challenge.getValue())));
    assertThat(options.getRpId(), equalTo(TEST_RP_ID));
    assertThat(options.getTimeout(), equalTo(30000L));
    assertThat(options.getUserVerification(), equalTo("preferred"));
    assertThat(options.getAllowCredentials(), hasSize(1));
    assertThat(options.getAllowCredentials().get(0).getId(), equalTo("existing-id"));
    assertThat(options.getAllowCredentials().get(0).getTransports(), empty());
  }

  @Test
  void verificationUpdatesCounterAndLastUsedTime() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    IamPasskey passkey = registeredPasskey(authenticator);
    when(passkeyRepository.findByCredentialIdForUpdate(authenticator.getCredentialIdBase64Url()))
      .thenReturn(Optional.of(passkey));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);
    PasskeyAssertionDTO assertion = assertionFor(authenticator, base64Url(challenge.getValue()),
        TEST_ORIGIN, false, 3, base64Url(TEST_UUID.getBytes(StandardCharsets.UTF_8)));

    IamPasskey used = service.verifyPasskey(account, challenge, assertion);

    assertThat(used.getSignCount(), equalTo(3L));
    assertThat(used.getLastUsedTime().toInstant(), equalTo(NOW));
    verify(passkeyRepository).saveAndFlush(passkey);
    verify(passkeyRepository).save(passkey);
    ArgumentCaptor<ApplicationEvent> event = ArgumentCaptor.forClass(ApplicationEvent.class);
    verify(eventPublisher, times(2)).publishEvent(event.capture());
    assertThat(event.getAllValues().get(1),
        instanceOf(PasskeyVerifiedEvent.class));
  }

  @Test
  void verificationAcceptsPaddedCredentialId() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    IamPasskey passkey = registeredPasskey(authenticator);
    when(passkeyRepository.findByCredentialIdForUpdate(authenticator.getCredentialIdBase64Url()))
      .thenReturn(Optional.of(passkey));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge.getValue()), TEST_ORIGIN, false, 2, null);
    assertion.setId(assertion.getId() + "==");

    assertThat(service.verifyPasskey(account, challenge, assertion).getSignCount(), equalTo(2L));
  }

  @Test
  void verificationOfUnknownCredentialFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    when(passkeyRepository.findByCredentialIdForUpdate(anyString())).thenReturn(Optional.empty());
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge.getValue()), TEST_ORIGIN, false, 1, null);

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.verifyPasskey(account, challenge, assertion));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.UNKNOWN_CREDENTIAL_MESSAGE));
  }

  @Test
  void verificationOfCredentialOfAnotherAccountFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    IamAccount other = IamAccount.newAccount();
    other.setId(43L);
    other.setUsername(OTHER_USERNAME);
    IamPasskey passkey = new IamPasskey(NOW, other);
    passkey.setCredentialId(authenticator.getCredentialIdBase64Url());
    when(passkeyRepository.findByCredentialIdForUpdate(authenticator.getCredentialIdBase64Url()))
      .thenReturn(Optional.of(passkey));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge.getValue()), TEST_ORIGIN, false, 1, null);

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.verifyPasskey(account, challenge, assertion));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.UNKNOWN_CREDENTIAL_MESSAGE));
  }

  @Test
  void verificationWithForeignUserHandleFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    IamPasskey passkey = registeredPasskey(authenticator);
    when(passkeyRepository.findByCredentialIdForUpdate(authenticator.getCredentialIdBase64Url()))
      .thenReturn(Optional.of(passkey));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);
    PasskeyAssertionDTO assertion = assertionFor(authenticator, base64Url(challenge.getValue()),
        TEST_ORIGIN, false, 1, base64Url("someone-else".getBytes(StandardCharsets.UTF_8)));

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.verifyPasskey(account, challenge, assertion));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.USER_HANDLE_MISMATCH_MESSAGE));
    assertThat(passkey.getSignCount(), equalTo(0L));
  }

  @Test
  void verificationWithReplayedCounterFailsAndKeepsCounter() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    IamPasskey passkey = registeredPasskey(authenticator);
    passkey.setSignCount(10);
    when(passkeyRepository.findByCredentialIdForUpdate(authenticator.getCredentialIdBase64Url()))
      .thenReturn(Optional.of(passkey));
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.AUTHENTICATION);
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge.getValue()), TEST_ORIGIN, false, 10, null);

    assertThrows(PasskeyCeremonyException.class,
        () -> service.verifyPasskey(account, challenge, assertion));
    assertThat(passkey.getSignCount(), equalTo(10L));
    assertThat(passkey.getLastUsedTime(), nullValue());
  }

  @Test
  void verificationWithRegistrationChallengeFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyChallenge challenge = service.createChallenge(account, Purpose.REGISTRATION);
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge.getValue()), TEST_ORIGIN, false, 1, null);

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.verifyPasskey(account, challenge, assertion));
    assertThat(e.getMessage(), equalTo(DefaultIamPasskeyService.CHALLENGE_MISMATCH_MESSAGE));
  }

  @Test
  void removePasskeyDeletesAndNotifies() {
    IamPasskey passkey = new IamPasskey(NOW, account);
    passkey.setUuid("passkey-uuid");
    passkey.setLabel("my key");
    when(passkeyRepository.findByUuidAndAccountId("passkey-uuid", 42L))
      .thenReturn(Optional.of(passkey));

    IamPasskey removed = service.removePasskey(account, "passkey-uuid");

    assertThat(removed, equalTo(passkey));
    verify(passkeyRepository).delete(passkey);
    verify(accountService).saveAccount(account);
    verify(notificationFactory).createPasskeyRemovedMessage(account, passkey);
    ArgumentCaptor<ApplicationEvent> event = ArgumentCaptor.forClass(ApplicationEvent.class);
    verify(eventPublisher).publishEvent(event.capture());
    assertThat(event.getValue(), instanceOf(PasskeyRemovedEvent.class));
  }

  @Test
  void lastPasskeyCannotBeRemovedWhenPasskeysAreMandatory() {
    properties.setMandatory(true);
    IamPasskey passkey = new IamPasskey(NOW, account);
    passkey.setUuid("passkey-uuid");
    passkey.setLabel("my key");
    when(passkeyRepository.findByUuidAndAccountId("passkey-uuid", 42L))
      .thenReturn(Optional.of(passkey));
    when(passkeyRepository.countByAccountId(42L)).thenReturn(1L);

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> service.removePasskey(account, "passkey-uuid"));
    assertThat(e.getMessage(),
        equalTo(DefaultIamPasskeyService.LAST_PASSKEY_MANDATORY_MESSAGE));
    verify(passkeyRepository, never()).delete(any());

    // With a second passkey registered the removal goes through
    when(passkeyRepository.countByAccountId(42L)).thenReturn(2L);
    assertThat(service.removePasskey(account, "passkey-uuid"), equalTo(passkey));
    verify(passkeyRepository).delete(passkey);
  }

  @Test
  void removeUnknownPasskeyFails() {
    when(passkeyRepository.findByUuidAndAccountId(anyString(), anyLong()))
      .thenReturn(Optional.empty());

    assertThrows(PasskeyNotFoundException.class, () -> service.removePasskey(account, "nope"));
    verify(passkeyRepository, never()).delete(any());
  }

  @Test
  void removeAllPasskeysDeletesEverythingAndNotifiesOnce() {
    IamPasskey first = new IamPasskey(NOW, account);
    first.setLabel("first");
    IamPasskey second = new IamPasskey(NOW, account);
    second.setLabel("second");
    when(passkeyRepository.findByAccountId(42L)).thenReturn(List.of(first, second));

    List<IamPasskey> removed = service.removeAllPasskeys(account);

    assertThat(removed, hasSize(2));
    verify(passkeyRepository).deleteAll(List.of(first, second));
    verify(accountService).saveAccount(account);
    verify(notificationFactory).createPasskeysResetMessage(account);
    verify(eventPublisher, times(2)).publishEvent(any(PasskeyRemovedEvent.class));
  }

  @Test
  void removeAllPasskeysOnEmptyAccountIsNoOp() {
    when(passkeyRepository.findByAccountId(42L)).thenReturn(List.of());

    assertThat(service.removeAllPasskeys(account), empty());
    verify(passkeyRepository, never()).deleteAll(any());
    verify(notificationFactory, never()).createPasskeysResetMessage(any());
  }
}
