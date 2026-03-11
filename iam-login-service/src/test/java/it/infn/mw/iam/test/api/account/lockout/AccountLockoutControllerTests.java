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
package it.infn.mw.iam.test.api.account.lockout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import it.infn.mw.iam.api.account.lockout.AccountLockoutController;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

@ExtendWith(MockitoExtension.class)
class AccountLockoutControllerTests {

  @Mock
  private IamAccountLoginLockoutRepository lockoutRepo;

  private AccountLockoutController controller;
  private IamAccount account;

  @BeforeEach
  void setup() {
    controller = new AccountLockoutController(lockoutRepo);
    account = new IamAccount();
    account.setUuid("uuid-1");
    account.setUsername("testuser");
  }

  @Test
  void getLockoutStatusReturnsSuspended() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    long future = System.currentTimeMillis() + 60_000;
    lockout.setSuspendedUntil(new Date(future));
    when(lockoutRepo.findByAccountUuid("uuid-1")).thenReturn(Optional.of(lockout));

    ResponseEntity<Map<String, Object>> r = controller.getLockoutStatus("uuid-1");
    assertEquals(true, r.getBody().get("suspended"));
    assertEquals(future, r.getBody().get("suspendedUntil"));
  }

  @Test
  void getLockoutStatusReturnsNotSuspendedWhenEmpty() {
    when(lockoutRepo.findByAccountUuid("uuid-1")).thenReturn(Optional.empty());

    ResponseEntity<Map<String, Object>> r = controller.getLockoutStatus("uuid-1");
    assertEquals(false, r.getBody().get("suspended"));
  }

  @Test
  void getLockoutStatusReturnsNotSuspendedWhenExpired() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    lockout.setSuspendedUntil(new Date(System.currentTimeMillis() - 1_000));
    when(lockoutRepo.findByAccountUuid("uuid-1")).thenReturn(Optional.of(lockout));

    ResponseEntity<Map<String, Object>> r = controller.getLockoutStatus("uuid-1");
    assertEquals(false, r.getBody().get("suspended"));
  }

  @Test
  void getLockoutStatusReturnsNotSuspendedWhenNullSuspendedUntil() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    when(lockoutRepo.findByAccountUuid("uuid-1")).thenReturn(Optional.of(lockout));

    ResponseEntity<Map<String, Object>> r = controller.getLockoutStatus("uuid-1");
    assertEquals(false, r.getBody().get("suspended"));
  }

  @Test
  void getAllSuspendedUsersReturnsUuids() {
    when(lockoutRepo.findAllSuspendedUsers()).thenReturn(List.of("uuid-a", "uuid-b"));

    ResponseEntity<List<String>> r = controller.getAllSuspendedUsers();
    assertEquals(2, r.getBody().size());
  }
}
