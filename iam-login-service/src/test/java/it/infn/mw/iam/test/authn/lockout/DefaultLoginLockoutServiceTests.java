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

import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.LockedException;

import it.infn.mw.iam.authn.lockout.DefaultLoginLockoutService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LoginLockoutProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

@ExtendWith(MockitoExtension.class)
class DefaultLoginLockoutServiceTests {

  private static final String USERNAME = "testuser";

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
    lockoutProps.setMaxFailedAttempts(2);
    lockoutProps.setLockoutMinutes(30);
    lockoutProps.setMaxConcurrentFailures(2);

    when(iamProperties.getLoginLockout()).thenReturn(lockoutProps);
    service = new DefaultLoginLockoutService(lockoutRepo, accountRepo, iamProperties);

    account = new IamAccount();
    account.setId(1L);
    account.setUsername(USERNAME);
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
  void blocksLoginWhenSuspended() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(new Date(System.currentTimeMillis() + 60000));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    assertThrows(LockedException.class, () -> service.checkIamAccountLockout(USERNAME));
  }

  @Test
  void successfulLoginDeletesRow() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setFailedAttempts(1);
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    service.resetFailedAttempts(USERNAME);
    verify(lockoutRepo).delete(lockout);
  }

  @Test
  void fullLifecycleSuspendSuspendDisable() {
    // Config: max-failed-attempts=2, max-concurrent-failures=2
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());

    // ROUND 1: 2 failures -> suspended
    service.recordFailedAttempt(USERNAME);
    ArgumentCaptor<IamAccountLoginLockout> captor = ArgumentCaptor.forClass(IamAccountLoginLockout.class);
    verify(lockoutRepo).save(captor.capture());
    IamAccountLoginLockout lockout = captor.getValue();

    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));
    service.recordFailedAttempt(USERNAME);

    assertEquals(1, lockout.getLockoutCount());
    assertNotNull(lockout.getSuspendedUntil());
    assertTrue(account.isActive());

    // Suspension expires
    lockout.setSuspendedUntil(new Date(System.currentTimeMillis() - 1000));
    service.checkIamAccountLockout(USERNAME);
    assertEquals(0, lockout.getFailedAttempts());
    assertNull(lockout.getSuspendedUntil());

    // ROUND 2: 2 failures -> suspended again
    service.recordFailedAttempt(USERNAME);
    service.recordFailedAttempt(USERNAME);
    assertEquals(2, lockout.getLockoutCount());
    assertTrue(account.isActive());

    // Suspension expires again
    lockout.setSuspendedUntil(new Date(System.currentTimeMillis() - 1000));
    service.checkIamAccountLockout(USERNAME);
    // ROUND 3: 2 failures -> account disabled, row deleted
    service.recordFailedAttempt(USERNAME);
    service.recordFailedAttempt(USERNAME);

    assertFalse(account.isActive());
    verify(accountRepo).save(account);
    verify(lockoutRepo).delete(lockout);
  }

  @Test
  void checkLockoutNoRecordIsNoop() {
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());
    assertDoesNotThrow(() -> service.checkIamAccountLockout(USERNAME));
  }

  @Test
  void recordFailedAttemptUnknownUserIsNoop() {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.empty());
    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void recordFailedAttemptInactiveAccountIsNoop() {
    account.setActive(false);
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void recordFailedAttemptWhileSuspendedIsNoop() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(new Date(System.currentTimeMillis() + 60_000));
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.of(lockout));

    service.recordFailedAttempt(USERNAME);
    verify(lockoutRepo, never()).save(any());
  }

  @Test
  void resetNoRowIsNoop() {
    when(lockoutRepo.findByAccountUsername(USERNAME)).thenReturn(Optional.empty());
    service.resetFailedAttempts(USERNAME);
    verify(lockoutRepo, never()).delete(any());
  }

}
