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
package it.infn.mw.iam.test.authn.lockout;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.LockedException;

import it.infn.mw.iam.authn.lockout.DefaultLoginLockoutService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LoginLockoutProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultLoginLockoutServiceTests {

  private static final String USERNAME = "testuser";
  private static final String UUID = "test-uuid-1234";

  @Mock
  private IamAccountLoginLockoutRepository lockoutRepo;

  @Mock
  private IamAccountRepository accountRepo;

  @Mock
  private IamProperties iamProperties;

  private LoginLockoutProperties lockoutProps;
  private DefaultLoginLockoutService service;
  private IamAccount account;

  @BeforeEach
  void setup() {
    lockoutProps = new LoginLockoutProperties();
    lockoutProps.setEnabled(true);
    lockoutProps.setMaxFailedAttemptsBeforeSuspension(2);
    lockoutProps.setSuspensionDurationMinutes(30);
    lockoutProps.setMaxSuspensionRounds(2);
    lockoutProps.setDisableAfterMaxSuspensionRounds(true);

    when(iamProperties.getLoginLockout()).thenReturn(lockoutProps);
    service = new DefaultLoginLockoutService(lockoutRepo, accountRepo, iamProperties);

    account = new IamAccount();
    account.setId(1L);
    account.setUsername(USERNAME);
    account.setUuid(UUID);
    account.setActive(true);
  }

  @Test
  void doesNothingWhenFeatureDisabled() {
    lockoutProps.setEnabled(false);

    assertDoesNotThrow(() -> service.checkIamAccountLockout(USERNAME));
    service.recordFailedAttempt(USERNAME);
    service.resetFailedAttempts(USERNAME);

    verify(lockoutRepo, never()).findByAccountUsername(any());
  }

  @Test
  void checkLockoutNoRecordDoesNothing() {
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());
    assertDoesNotThrow(() -> service.checkIamAccountLockout(USERNAME));
  }

  @Test
  void blocksLoginWhenSuspended() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    assertThrows(LockedException.class, () -> service.checkIamAccountLockout(USERNAME));
  }

  @Test
  void checkLockoutResetsExpiredSuspension() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(2);
    lockout.setFirstFailureTime(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));
    lockout.setSuspendedUntil(Date.from(Instant.now().minus(1, ChronoUnit.SECONDS)));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    service.checkIamAccountLockout(USERNAME);

    assertEquals(0, lockout.getFailedAttempts());
    assertNull(lockout.getFirstFailureTime());
    assertNull(lockout.getSuspendedUntil());
    verify(lockoutRepo).save(lockout);
  }

  @Test
  void checkLockoutRecordExistsNeverSuspendedDoesNothing() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(1);
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    assertDoesNotThrow(() -> service.checkIamAccountLockout(USERNAME));
    assertEquals(1, lockout.getFailedAttempts());
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void recordUnknownUserDoesNothing() {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.empty());
    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void recordInactiveAccountDoesNothing() {
    account.setActive(false);
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void recordWhileStillSuspendedDoesNothing() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void firstFailureSetsFirstFailureTime() {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());

    service.recordFailedAttempt(USERNAME);

    ArgumentCaptor<IamAccountLoginLockout> captor = ArgumentCaptor.forClass(IamAccountLoginLockout.class);
    verify(lockoutRepo).save(captor.capture());
    IamAccountLoginLockout saved = captor.getValue();

    assertEquals(1, saved.getFailedAttempts());
    assertNotNull(saved.getFirstFailureTime());
    assertNull(saved.getSuspendedUntil());
    assertEquals(0, saved.getLockoutCount());
  }

  @Test
  void secondFailureKeepsOriginalFirstFailureTime() {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());
    lockoutProps.setMaxFailedAttemptsBeforeSuspension(5);

    service.recordFailedAttempt(USERNAME);
    ArgumentCaptor<IamAccountLoginLockout> captor = ArgumentCaptor.forClass(IamAccountLoginLockout.class);
    verify(lockoutRepo).save(captor.capture());
    IamAccountLoginLockout lockout = captor.getValue();
    Date first = lockout.getFirstFailureTime();

    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));
    service.recordFailedAttempt(USERNAME);

    assertEquals(2, lockout.getFailedAttempts());
    assertEquals(first, lockout.getFirstFailureTime());
  }

  @Test
  void reachingThresholdSuspendsAccount() {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());

    service.recordFailedAttempt(USERNAME);
    ArgumentCaptor<IamAccountLoginLockout> captor = ArgumentCaptor.forClass(IamAccountLoginLockout.class);
    verify(lockoutRepo).save(captor.capture());
    IamAccountLoginLockout lockout = captor.getValue();

    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));
    service.recordFailedAttempt(USERNAME);

    assertEquals(1, lockout.getLockoutCount());
    assertNotNull(lockout.getSuspendedUntil());
    assertTrue(account.isActive());
  }

  @Test
  void resetDeletesRow() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    service.resetFailedAttempts(USERNAME);
    verify(lockoutRepo).delete(lockout);
  }

  @Test
  void resetNoRowDoesNothing() {
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());
    service.resetFailedAttempts(USERNAME);
    verify(lockoutRepo, never()).delete(any());
  }

  @Test
  void disableAccountAfterMaxSuspensionRounds() {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());

    // ROUND 1: 2 failures => suspended
    service.recordFailedAttempt(USERNAME);
    ArgumentCaptor<IamAccountLoginLockout> captor = ArgumentCaptor.forClass(IamAccountLoginLockout.class);
    verify(lockoutRepo).save(captor.capture());
    IamAccountLoginLockout lockout = captor.getValue();
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    service.recordFailedAttempt(USERNAME);
    assertEquals(1, lockout.getLockoutCount());
    assertTrue(account.isActive());

    // Suspension expires
    lockout.setSuspendedUntil(Date.from(Instant.now().minus(1, ChronoUnit.SECONDS)));
    service.checkIamAccountLockout(USERNAME);
    service.recordFailedAttempt(USERNAME);
    service.recordFailedAttempt(USERNAME);
    assertEquals(2, lockout.getLockoutCount());

    // Suspension expires
    lockout.setSuspendedUntil(Date.from(Instant.now().minus(1, ChronoUnit.SECONDS)));
    service.checkIamAccountLockout(USERNAME);
    service.recordFailedAttempt(USERNAME);
    service.recordFailedAttempt(USERNAME);

    assertFalse(account.isActive());
    verify(accountRepo).save(account);
    verify(lockoutRepo).delete(lockout);
  }

  @Test
  void keepsSuspendingIndefinitelyWhenDisableIsFalse() {
    lockoutProps.setDisableAfterMaxSuspensionRounds(false);

    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());

    // ROUND 1
    service.recordFailedAttempt(USERNAME);
    ArgumentCaptor<IamAccountLoginLockout> captor = ArgumentCaptor.forClass(IamAccountLoginLockout.class);
    verify(lockoutRepo).save(captor.capture());
    IamAccountLoginLockout lockout = captor.getValue();
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));
    service.recordFailedAttempt(USERNAME);

    // Expire + ROUND 2
    lockout.setSuspendedUntil(Date.from(Instant.now().minus(1, ChronoUnit.SECONDS)));
    service.checkIamAccountLockout(USERNAME);
    service.recordFailedAttempt(USERNAME);
    service.recordFailedAttempt(USERNAME);

    // Expire + ROUND 3: would disable with default, but now just suspends again
    lockout.setSuspendedUntil(Date.from(Instant.now().minus(1, ChronoUnit.SECONDS)));
    service.checkIamAccountLockout(USERNAME);
    service.recordFailedAttempt(USERNAME);
    service.recordFailedAttempt(USERNAME);

    assertEquals(3, lockout.getLockoutCount());
    assertNotNull(lockout.getSuspendedUntil());
    assertTrue(account.isActive());
    verify(accountRepo, never()).save(account);
  }

  @Test
  void adminRevokeLockoutDeletesRow() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
    when(lockoutRepo.findByAccountUuid(UUID)).thenReturn(Optional.of(lockout));

    service.adminRevokeLockout(UUID);
    verify(lockoutRepo).delete(lockout);
  }

  @Test
  void adminRevokeLockoutNoRowPresent() {
    when(lockoutRepo.findByAccountUuid(UUID)).thenReturn(Optional.empty());
    service.adminRevokeLockout(UUID);
    verify(lockoutRepo, never()).delete(any());
  }

  @Test
  void validateDisabledDoesNotThrow() {
    lockoutProps.setEnabled(false);
    assertDoesNotThrow(() -> service.validateConfiguration());
  }

  @Test
  void validateValidConfigDoesNotThrow() {
    assertDoesNotThrow(() -> service.validateConfiguration());
  }

  @Test
  void validateZeroMaxFailedAttemptsBeforeSuspensionThrows() {
    lockoutProps.setMaxFailedAttemptsBeforeSuspension(0);
    assertThrows(IllegalStateException.class, () -> service.validateConfiguration());
  }

  @Test
  void validateZeroSuspensionDurationMinutesThrows() {
    lockoutProps.setSuspensionDurationMinutes(0);
    assertThrows(IllegalStateException.class, () -> service.validateConfiguration());
  }

  @Test
  void validateZeroMaxConcurrentWithDisableTrueThrows() {
    lockoutProps.setMaxSuspensionRounds(0);
    lockoutProps.setDisableAfterMaxSuspensionRounds(true);
    assertThrows(IllegalStateException.class, () -> service.validateConfiguration());
  }

  @Test
  void validateZeroMaxConcurrentWithDisableFalseDoesNotThrow() {
    lockoutProps.setMaxSuspensionRounds(0);
    lockoutProps.setDisableAfterMaxSuspensionRounds(false);
    assertDoesNotThrow(() -> service.validateConfiguration());
  }
}
