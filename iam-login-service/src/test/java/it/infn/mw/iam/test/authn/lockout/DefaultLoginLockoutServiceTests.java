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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.LockedException;

import it.infn.mw.iam.authn.lockout.DefaultLoginLockoutService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LoginLockoutProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultLoginLockoutServiceTests {

  private static final String USERNAME = "testuser";
  private static final String UUID = "test-uuid-1234";

  @Mock
  private IamAccountLoginLockoutRepository lockoutRepo;

  @Mock
  private IamAccountService accountService;

  @Mock
  private IamProperties iamProperties;

  private Clock clock = Clock.systemUTC();

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
    service = new DefaultLoginLockoutService(clock, accountService, lockoutRepo, iamProperties);

    account = new IamAccount();
    account.setId(1L);
    account.setUsername(USERNAME);
    account.setUuid(UUID);
    account.setActive(true);
  }

  @Test
  void checkLockoutNoRecordDoesNothing() {
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());
    assertDoesNotThrow(() -> service.checkIamAccountLockout(USERNAME));
  }

  @Test
  void blocksLoginWhenSuspended() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(Date.from(clock.instant().plus(1, ChronoUnit.HOURS)));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    assertThrows(LockedException.class, () -> service.checkIamAccountLockout(USERNAME));
  }

  @Test
  void checkLockoutAllowsExpiredSuspensionWithoutModifyingState() {
    Date firstFailureTime = Date.from(clock.instant().minus(2, ChronoUnit.HOURS));
    Date suspendedUntil = Date.from(clock.instant().minus(1, ChronoUnit.HOURS));

    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(2);
    lockout.setLockoutCount(1);
    lockout.setFirstFailureTime(firstFailureTime);
    lockout.setSuspendedUntil(suspendedUntil);

    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    assertDoesNotThrow(() -> service.checkIamAccountLockout(USERNAME));

    assertEquals(2, lockout.getFailedAttempts());
    assertEquals(1, lockout.getLockoutCount());
    assertEquals(firstFailureTime, lockout.getFirstFailureTime());
    assertEquals(suspendedUntil, lockout.getSuspendedUntil());

    verify(lockoutRepo, never()).save(any());
    verify(lockoutRepo, never()).delete(any());
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

    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.empty());
    assertDoesNotThrow(() -> service.recordFailedAttempt(USERNAME));
    verifyNoInteractions(lockoutRepo);
    verify(accountService, never()).loginFailedAttempt(any());
  }

  @Test
  void recordInactiveAccountDoesNothing() {
    account.setActive(false);
    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void recordWhileStillSuspendedDoesNothing() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(Date.from(clock.instant().plus(1, ChronoUnit.HOURS)));
    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void firstFailureSetsFirstFailureTime() {
    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());

    when(accountService.loginFailedAttempt(account)).thenAnswer(invocation -> {
      IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
      lockout.setFailedAttempts(1);
      lockout.setFirstFailureTime(Date.from(clock.instant()));
      account.setLockoutInfo(lockout);
      return account;
    });

    service.recordFailedAttempt(USERNAME);

    verify(accountService).loginFailedAttempt(account);
    verify(accountService, never()).suspendAccount(any());
    verify(accountService, never()).disableAccount(any());
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void recordsFailureWithoutSuspendingBelowThreshold() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(0);
    account.setLockoutInfo(lockout);

    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    when(accountService.loginFailedAttempt(account)).thenAnswer(invocation -> {
      lockout.setFailedAttempts(1);
      return account;
    });

    service.recordFailedAttempt(USERNAME);

    verify(accountService).loginFailedAttempt(account);
    verify(accountService, never()).suspendAccount(any());
    verify(accountService, never()).disableAccount(any());
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void reachingThresholdSuspendsAccount() {
    int threshold = lockoutProps.getMaxFailedAttemptsBeforeSuspension();

    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(threshold - 1);
    lockout.setLockoutCount(0);
    account.setLockoutInfo(lockout);

    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    when(accountService.loginFailedAttempt(account)).thenAnswer(invocation -> {
      lockout.setFailedAttempts(lockout.getFailedAttempts() + 1);
      return account;
    });

    service.recordFailedAttempt(USERNAME);

    assertEquals(threshold, lockout.getFailedAttempts());
    assertEquals(1, lockout.getLockoutCount());

    verify(accountService).loginFailedAttempt(account);
    verify(lockoutRepo).save(lockout);
    verify(accountService).suspendAccount(account);
    verify(accountService, never()).disableAccount(any());
  }

  @Test
  void resetDeletesRow() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);

    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountId(account.getId())).thenReturn(Optional.of(lockout));

    service.resetFailedAttempts(USERNAME);

    verify(accountService).findByUsernameForUpdate(USERNAME);
    verify(accountService).unsuspendAccount(account);
  }

  @Test
  void resetNoRowDoesNothing() {
    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountId(account.getId())).thenReturn(Optional.empty());

    service.resetFailedAttempts(USERNAME);

    verify(accountService).unsuspendAccount(account);
  }

  @Test
  void disableAccountAfterMaxSuspensionRounds() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(1);
    lockout.setLockoutCount(2);
    account.setLockoutInfo(lockout);

    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    // Simulate the state change owned by IamAccountService.
    when(accountService.loginFailedAttempt(account)).thenAnswer(invocation -> {
      lockout.setFailedAttempts(lockout.getFailedAttempts() + 1);
      return account;
    });

    service.recordFailedAttempt(USERNAME);

    assertEquals(2, lockout.getFailedAttempts());
    assertEquals(3, lockout.getLockoutCount());

    verify(accountService).loginFailedAttempt(account);
    verify(lockoutRepo).save(lockout);
    verify(accountService).suspendAccount(account);
    verify(accountService).disableAccount(account);
  }

  @Test
  void keepsSuspendingBeyondLimitWhenDisableIsFalse() {
    lockoutProps.setDisableAfterMaxSuspensionRounds(false);

    int previousRounds = lockoutProps.getMaxSuspensionRounds();
    int threshold = lockoutProps.getMaxFailedAttemptsBeforeSuspension();

    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(threshold - 1);
    lockout.setLockoutCount(previousRounds);
    account.setLockoutInfo(lockout);

    when(accountService.findByUsernameForUpdate(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    when(accountService.loginFailedAttempt(account)).thenAnswer(invocation -> {
      lockout.setFailedAttempts(lockout.getFailedAttempts() + 1);
      return account;
    });

    service.recordFailedAttempt(USERNAME);

    assertEquals(threshold, lockout.getFailedAttempts());
    assertEquals(previousRounds + 1, lockout.getLockoutCount());

    verify(accountService).loginFailedAttempt(account);
    verify(lockoutRepo).save(lockout);
    verify(accountService).suspendAccount(account);
    verify(accountService, never()).disableAccount(any());
  }

  @Test
  void adminRevokeLockoutDeletesRow() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(Date.from(clock.instant().plus(1, ChronoUnit.HOURS)));
    when(lockoutRepo.findByAccountUuid(UUID)).thenReturn(Optional.of(lockout));

    service.adminRevokeLockout(UUID);
    verify(accountService).unsuspendAccount(account);
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
