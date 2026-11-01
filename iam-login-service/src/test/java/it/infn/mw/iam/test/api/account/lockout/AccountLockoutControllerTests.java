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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.persistence.EntityNotFoundException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import it.infn.mw.iam.api.account.lockout.AccountLockoutController;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

@ExtendWith(MockitoExtension.class)
class AccountLockoutControllerTests {

  @Mock
  private IamAccountLoginLockoutRepository lockoutRepo;

  @Mock
  private IamAccountService accountService;

  private MockMvc mvc;

  private Clock clock;

  private AccountLockoutController lockoutController;
  private IamAccount account;

  @BeforeEach
  void setup() {
    clock = Clock.systemUTC();
    lockoutController = new AccountLockoutController(clock, lockoutRepo, accountService);
    account = new IamAccount();
    account.setUuid("uuid-1");
    account.setUsername("testuser");
    mvc = MockMvcBuilders.standaloneSetup(lockoutController).build();
  }

  @Test
  void getLockoutStatusReturnsSuspended() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    Instant now = clock.instant();
    Instant future = now.plusSeconds(60);
    lockout.setSuspendedUntil(Date.from(future));
    account.setLockoutInfo(lockout);
    when(accountService.findByUuid("uuid-1")).thenReturn(Optional.of(account));

    ResponseEntity<Map<String, Object>> r = lockoutController.getLockoutStatus("uuid-1");
    assertEquals(true, r.getBody().get("suspended"));
    assertEquals(Date.from(future), r.getBody().get("suspendedUntil"));
  }

  @Test
  void getLockoutStatusReturnsNotSuspendedWhenExpired() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    Instant now = clock.instant();
    lockout.setSuspendedUntil(Date.from(now.minusSeconds(1)));
    account.setLockoutInfo(lockout);
    when(accountService.findByUuid("uuid-1")).thenReturn(Optional.of(account));

    ResponseEntity<Map<String, Object>> r = lockoutController.getLockoutStatus("uuid-1");
    assertEquals(false, r.getBody().get("suspended"));
  }

  @Test
  void getLockoutStatusReturnsNotSuspendedWhenNullSuspendedUntil() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout(account);
    account.setLockoutInfo(lockout);
    when(accountService.findByUuid("uuid-1")).thenReturn(Optional.of(account));

    ResponseEntity<Map<String, Object>> r = lockoutController.getLockoutStatus("uuid-1");
    assertEquals(false, r.getBody().get("suspended"));
  }

  @Test
  void getAllSuspendedUsersReturnsUuids() {
    when(lockoutRepo.findAllSuspendedUsers()).thenReturn(List.of("a", "b"));

    ResponseEntity<List<String>> r = lockoutController.getAllSuspendedUsers();
    assertEquals(2, r.getBody().size());
  }

  @Test
  void revokeLockoutDelegatesToService() {
    ResponseEntity<Map<String, Object>> r = lockoutController.revokeLockout("uuid-1");

    verify(accountService).resetLoginLockout("uuid-1", LoginLockoutResetReason.ADMIN_REVOKE);
    assertEquals(true, r.getBody().get("unlocked"));
  }

  @Test
  void getLockoutStatusReturnsNotFoundWhenEmpty() throws Exception {
    when(accountService.findByUuid("uuid-1")).thenReturn(Optional.empty());

    mvc.perform(get("/iam/account/{uuid}/lockout", "uuid-1"))
      .andExpect(status().isNotFound())
      .andExpect(content().string("UUID uuid-1 not found!"));

    verify(accountService).findByUuid("uuid-1");
  }

  @Test
  void revokeLockoutReturnsNotFoundWhenEmpty() throws Exception {
    when(accountService.resetLoginLockout("uuid-1", LoginLockoutResetReason.ADMIN_REVOKE))
      .thenThrow(new EntityNotFoundException("UUID uuid-1 not found!"));

    mvc.perform(delete("/iam/account/{uuid}/lockout", "uuid-1"))
      .andExpect(status().isNotFound())
      .andExpect(content().string("UUID uuid-1 not found!"));

    verify(accountService).resetLoginLockout("uuid-1", LoginLockoutResetReason.ADMIN_REVOKE);
  }
}
