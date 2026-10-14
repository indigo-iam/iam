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
package it.infn.mw.iam.test.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;

import javax.persistence.EntityNotFoundException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.audit.events.account.AccountLoginLockoutResetEvent;
import it.infn.mw.iam.audit.events.account.AccountLoginSuspendedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.group.DefaultIamGroupService;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.user.DefaultIamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.registration.TokenGenerator;

@ExtendWith(MockitoExtension.class)
class IamAccountLoginLockoutServiceTests {

  private static final Instant NOW = Instant.parse("2026-10-13T10:00:00Z");
  private static final Duration WINDOW = Duration.ofMinutes(10);
  private static final Duration LOCK_DURATION = Duration.ofMinutes(5);
  private static final String UUID = "account-uuid";

  @Mock
  IamAccountRepository accountRepo;
  @Mock
  ApplicationEventPublisher events;
  @Mock
  NotificationFactory notifications;

  private final IamProperties properties = new IamProperties();
  private DefaultIamAccountService service;
  private IamAccount account;

  @BeforeEach
  void setUp() {
    properties.getLoginLockout().setEnabled(true);
    properties.getLoginLockout().setMaxFailedAttempts(3);
    properties.getLoginLockout().setObservationWindow(WINDOW);
    properties.getLoginLockout().setLockDuration(LOCK_DURATION);
    account = new IamAccount();
    account.setUuid(UUID);
    account.setUsername("alice");
    account.setActive(true);
    service = new DefaultIamAccountService(Clock.fixed(NOW, ZoneOffset.UTC), accountRepo,
        mock(IamGroupRepository.class), mock(IamAuthoritiesRepository.class),
        mock(PasswordEncoder.class), events, mock(TokenRevocationService.class),
        mock(IamAccountClientRepository.class), notifications, properties,
        mock(DefaultIamGroupService.class), mock(TokenGenerator.class),
        mock(IamAupSignatureRepository.class), mock(IamTotpMfaRepository.class));
  }

  private void loadForUpdate() {
    when(accountRepo.findByUuidForUpdate(UUID)).thenReturn(Optional.of(account));
  }

  private void saveAccount() {
    when(accountRepo.save(account)).thenReturn(account);
  }

  private IamAccountLoginLockout previousFailures(int failures, Instant firstFailure) {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(failures);
    lockout.setFirstFailureTime(Date.from(firstFailure));
    account.setLockoutInfo(lockout);
    return lockout;
  }

  private void assertNoWriteOrNotification() {
    verify(accountRepo, never()).save(any());
    verifyNoInteractions(events, notifications);
  }

  @Test
  void firstFailureCreatesLinkedLockoutAndUpdatesAccount() {
    loadForUpdate();
    saveAccount();
    assertSame(account, service.loginFailedAttempt(UUID));
    IamAccountLoginLockout lockout = account.getLockoutInfo();
    assertSame(account, lockout.getAccount());
    assertEquals(1, lockout.getFailedAttempts());
    assertEquals(Date.from(NOW), lockout.getFirstFailureTime());
    assertNull(lockout.getSuspendedUntil());
    assertEquals(Date.from(NOW), account.getLastUpdateTime());
    verify(accountRepo).save(account);
    verifyNoInteractions(events, notifications);
  }

  @Test
  void failureWithinWindowPreservesItsStart() {
    loadForUpdate();
    saveAccount();
    IamAccountLoginLockout lockout = previousFailures(1, NOW.minusSeconds(30));
    service.loginFailedAttempt(UUID);
    assertEquals(2, lockout.getFailedAttempts());
    assertEquals(Date.from(NOW.minusSeconds(30)), lockout.getFirstFailureTime());
    verifyNoInteractions(events, notifications);
  }

  @ParameterizedTest
  @ValueSource(longs = {600, 601})
  void expiredObservationWindowStartsNewRound(long ageSeconds) {
    loadForUpdate();
    saveAccount();
    IamAccountLoginLockout lockout = previousFailures(2, NOW.minusSeconds(ageSeconds));
    lockout.setLockoutCount(4);
    service.loginFailedAttempt(UUID);
    assertEquals(1, lockout.getFailedAttempts());
    assertEquals(Date.from(NOW), lockout.getFirstFailureTime());
    assertEquals(4, lockout.getLockoutCount());
    assertNull(lockout.getSuspendedUntil());
    verifyNoInteractions(events, notifications);
  }

  @Test
  void thresholdSuspendsAndPublishesOneEvent() {
    loadForUpdate();
    saveAccount();
    IamAccountLoginLockout lockout = previousFailures(2, NOW.minusSeconds(30));
    lockout.setLockoutCount(2);
    service.loginFailedAttempt(UUID);
    assertEquals(3, lockout.getFailedAttempts());
    assertEquals(3, lockout.getLockoutCount());
    assertEquals(Date.from(NOW.plus(LOCK_DURATION)), lockout.getSuspendedUntil());
    ArgumentCaptor<AccountLoginSuspendedEvent> event =
        ArgumentCaptor.forClass(AccountLoginSuspendedEvent.class);
    verify(events).publishEvent(event.capture());
    assertSame(account, event.getValue().getAccount());
    verifyNoInteractions(notifications);
    verifyNoMoreInteractions(events);
  }

  @Test
  void failureDuringSuspensionDoesNotExtendItOrNotifyAgain() {
    loadForUpdate();
    IamAccountLoginLockout lockout = previousFailures(3, NOW.minusSeconds(30));
    lockout.setSuspendedUntil(Date.from(NOW.plusSeconds(60)));
    lockout.setLockoutCount(2);
    assertSame(account, service.loginFailedAttempt(UUID));
    assertEquals(3, lockout.getFailedAttempts());
    assertEquals(2, lockout.getLockoutCount());
    assertEquals(Date.from(NOW.plusSeconds(60)), lockout.getSuspendedUntil());
    assertNoWriteOrNotification();
  }

  @ParameterizedTest
  @ValueSource(longs = {0, 1})
  void expiredSuspensionStartsNewRoundPreservingHistory(long secondsSinceExpiry) {
    loadForUpdate();
    saveAccount();
    IamAccountLoginLockout lockout = previousFailures(3, NOW.minusSeconds(60));
    lockout.setSuspendedUntil(Date.from(NOW.minusSeconds(secondsSinceExpiry)));
    lockout.setLockoutCount(2);
    service.loginFailedAttempt(UUID);
    assertEquals(1, lockout.getFailedAttempts());
    assertEquals(Date.from(NOW), lockout.getFirstFailureTime());
    assertEquals(2, lockout.getLockoutCount());
    assertNull(lockout.getSuspendedUntil());
    verifyNoInteractions(events, notifications);
  }

  @Test
  void disabledFeatureDoesNotCreateLockout() {
    loadForUpdate();
    properties.getLoginLockout().setEnabled(false);
    assertSame(account, service.loginFailedAttempt(UUID));
    assertNull(account.getLockoutInfo());
    assertNoWriteOrNotification();
  }

  @Test
  void unknownUsernameDoesNotCreateAccountOrLockout() {
    when(accountRepo.findByUsernameForUpdate("missing")).thenReturn(Optional.empty());
    assertTrue(service.loginFailedAttemptByUsername("missing").isEmpty());
    assertNoWriteOrNotification();
  }

  @Test
  void failureByUsernameRecordsFailureOnResolvedAccount() {
    when(accountRepo.findByUsernameForUpdate("alice")).thenReturn(Optional.of(account));
    saveAccount();
    assertSame(account, service.loginFailedAttemptByUsername("alice").orElseThrow());
    assertEquals(1, account.getLockoutInfo().getFailedAttempts());
    verify(accountRepo, never()).findByUuidForUpdate(any());
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "\t"})
  void invalidUuidIsRejectedBeforeRepositoryAccess(String uuid) {
    assertThrows(IllegalArgumentException.class, () -> service.checkLoginAllowed(uuid));
    assertThrows(IllegalArgumentException.class, () -> service.loginFailedAttempt(uuid));
    assertThrows(IllegalArgumentException.class,
        () -> service.resetLoginLockout(uuid, LoginLockoutResetReason.ADMIN_REVOKE));
    verifyNoInteractions(accountRepo, events, notifications);
  }

  @Test
  void missingAccountIsRejected() {
    when(accountRepo.findByUuid(UUID)).thenReturn(Optional.empty());
    when(accountRepo.findByUuidForUpdate(UUID)).thenReturn(Optional.empty());
    assertThrows(UsernameNotFoundException.class, () -> service.checkLoginAllowed(UUID));
    assertThrows(EntityNotFoundException.class, () -> service.loginFailedAttempt(UUID));
    assertThrows(EntityNotFoundException.class,
        () -> service.resetLoginLockout(UUID, LoginLockoutResetReason.ADMIN_REVOKE));
    assertNoWriteOrNotification();
  }

  @Test
  void loginWithoutLockoutIsAllowed() {
    when(accountRepo.findByUuid(UUID)).thenReturn(Optional.of(account));
    assertDoesNotThrow(() -> service.checkLoginAllowed(UUID));
    assertNoWriteOrNotification();
  }

  @ParameterizedTest
  @ValueSource(longs = {-1, 0, 1})
  void loginCheckUsesExclusiveSuspensionEnd(long secondsUntilExpiry) {
    when(accountRepo.findByUuid(UUID)).thenReturn(Optional.of(account));
    IamAccountLoginLockout lockout = previousFailures(3, NOW.minusSeconds(60));
    lockout.setSuspendedUntil(Date.from(NOW.plusSeconds(secondsUntilExpiry)));
    if (secondsUntilExpiry > 0) {
      assertThrows(LockedException.class, () -> service.checkLoginAllowed(UUID));
    } else {
      assertDoesNotThrow(() -> service.checkLoginAllowed(UUID));
    }
    assertEquals(3, lockout.getFailedAttempts());
    assertNoWriteOrNotification();
  }

  @Test
  void disabledFeatureIgnoresSuspensionButStillRejectsDisabledAccount() {
    when(accountRepo.findByUuid(UUID)).thenReturn(Optional.of(account));
    properties.getLoginLockout().setEnabled(false);
    previousFailures(3, NOW).setSuspendedUntil(Date.from(NOW.plusSeconds(60)));
    assertDoesNotThrow(() -> service.checkLoginAllowed(UUID));
    account.setActive(false);
    assertThrows(DisabledException.class, () -> service.checkLoginAllowed(UUID));
    assertNoWriteOrNotification();
  }

  @ParameterizedTest
  @EnumSource(LoginLockoutResetReason.class)
  void resetClearsFailuresAndHistoryAndAuditsReason(LoginLockoutResetReason reason) {
    loadForUpdate();
    saveAccount();
    IamAccountLoginLockout lockout = previousFailures(3, NOW.minusSeconds(60));
    lockout.setSuspendedUntil(Date.from(NOW));
    lockout.setLockoutCount(2);
    assertSame(account, service.resetLoginLockout(UUID, reason));
    assertEquals(0, lockout.getFailedAttempts());
    assertNull(lockout.getFirstFailureTime());
    assertNull(lockout.getSuspendedUntil());
    assertEquals(0, lockout.getLockoutCount());
    assertEquals(Date.from(NOW), account.getLastUpdateTime());
    verify(accountRepo).save(account);
    ArgumentCaptor<AccountLoginLockoutResetEvent> event =
        ArgumentCaptor.forClass(AccountLoginLockoutResetEvent.class);
    verify(events).publishEvent(event.capture());
    assertSame(account, event.getValue().getAccount());
    assertEquals(reason, event.getValue().getReason());
    verifyNoMoreInteractions(events);
    verifyNoInteractions(notifications);
  }

  @ParameterizedTest
  @EnumSource(value = LoginLockoutResetReason.class, names = {"ADMIN_REVOKE", "PASSWORD_RESET"})
  void explicitResetCanClearActiveSuspensionOnDisabledAccount(LoginLockoutResetReason reason) {
    loadForUpdate();
    saveAccount();
    account.setActive(false);
    IamAccountLoginLockout lockout = previousFailures(3, NOW);
    lockout.setSuspendedUntil(Date.from(NOW.plusSeconds(60)));
    service.resetLoginLockout(UUID, reason);
    assertTrue(lockout.isCurrentRoundEmpty());
    assertFalse(account.isActive());
    verify(accountRepo).save(account);
  }

  @Test
  void successfulAuthenticationCannotClearActiveSuspension() {
    loadForUpdate();
    IamAccountLoginLockout lockout = previousFailures(3, NOW);
    lockout.setSuspendedUntil(Date.from(NOW.plusSeconds(60)));
    assertThrows(LockedException.class,
        () -> service.resetLoginLockout(UUID, LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION));
    assertEquals(3, lockout.getFailedAttempts());
    assertEquals(Date.from(NOW.plusSeconds(60)), lockout.getSuspendedUntil());
    assertNoWriteOrNotification();
  }

  @Test
  void successfulAuthenticationCannotResetDisabledAccountEvenWithoutLockout() {
    loadForUpdate();
    account.setActive(false);
    assertThrows(DisabledException.class,
        () -> service.resetLoginLockout(UUID, LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION));
    assertNoWriteOrNotification();
  }

  @ParameterizedTest
  @EnumSource(LoginLockoutResetReason.class)
  void resetWithoutLockoutIsNoOp(LoginLockoutResetReason reason) {
    loadForUpdate();
    assertSame(account, service.resetLoginLockout(UUID, reason));
    assertNull(account.getLockoutInfo());
    assertNoWriteOrNotification();
  }

  @Test
  void resetEmptyLockoutIsNoOp() {
    loadForUpdate();
    account.setLockoutInfo(new IamAccountLoginLockout(account));
    service.resetLoginLockout(UUID, LoginLockoutResetReason.ADMIN_REVOKE);
    assertNoWriteOrNotification();
  }

  @Test
  void resetClearsHistoricalCountEvenWhenCurrentRoundIsEmpty() {
    loadForUpdate();
    saveAccount();
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setLockoutCount(2);
    account.setLockoutInfo(lockout);
    service.resetLoginLockout(UUID, LoginLockoutResetReason.ADMIN_REVOKE);
    assertEquals(0, lockout.getLockoutCount());
    verify(accountRepo).save(account);
    verify(events).publishEvent(any(AccountLoginLockoutResetEvent.class));
  }

  @Test
  void nullResetReasonIsRejectedBeforeRepositoryAccess() {
    assertThrows(NullPointerException.class, () -> service.resetLoginLockout(UUID, null));
    verifyNoInteractions(accountRepo, events, notifications);
  }

  @Test
  void successfulAuthenticationClearsSuspensionWhenFeatureDisabled() {
    properties.getLoginLockout().setEnabled(false);
    loadForUpdate();
    saveAccount();

    IamAccountLoginLockout lockout = previousFailures(3, NOW);
    lockout.setSuspendedUntil(Date.from(NOW.plusSeconds(60)));
    lockout.setLockoutCount(2);

    IamAccount result = assertDoesNotThrow(
        () -> service.resetLoginLockout(UUID, LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION));

    assertSame(account, result);
    assertTrue(account.isActive());
    assertTrue(lockout.isCurrentRoundEmpty());
    assertEquals(0, lockout.getLockoutCount());
    assertEquals(Date.from(NOW), account.getLastUpdateTime());

    verify(accountRepo).save(account);

    ArgumentCaptor<AccountLoginLockoutResetEvent> event =
        ArgumentCaptor.forClass(AccountLoginLockoutResetEvent.class);

    verify(events).publishEvent(event.capture());
    assertSame(account, event.getValue().getAccount());
    assertEquals(LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION, event.getValue().getReason());

    verifyNoMoreInteractions(events);
    verifyNoInteractions(notifications);
  }

  @Test
  void successfulAuthenticationStillRejectsDisabledAccountWhenFeatureDisabled() {
    properties.getLoginLockout().setEnabled(false);
    loadForUpdate();
    account.setActive(false);

    IamAccountLoginLockout lockout = previousFailures(3, NOW);
    Date suspendedUntil = Date.from(NOW.plusSeconds(60));
    lockout.setSuspendedUntil(suspendedUntil);
    lockout.setLockoutCount(2);

    assertThrows(DisabledException.class,
        () -> service.resetLoginLockout(UUID, LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION));

    assertEquals(3, lockout.getFailedAttempts());
    assertEquals(Date.from(NOW), lockout.getFirstFailureTime());
    assertEquals(suspendedUntil, lockout.getSuspendedUntil());
    assertEquals(2, lockout.getLockoutCount());

    assertNoWriteOrNotification();
  }
}
