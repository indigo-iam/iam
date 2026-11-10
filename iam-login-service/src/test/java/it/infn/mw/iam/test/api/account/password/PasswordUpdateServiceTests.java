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
package it.infn.mw.iam.test.api.account.password;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.account.password_reset.DefaultPasswordResetService;
import it.infn.mw.iam.api.account.password_reset.error.BadUserPasswordError;
import it.infn.mw.iam.api.account.password_reset.error.InvalidPasswordError;
import it.infn.mw.iam.api.account.password_reset.error.UserNotActiveOrNotVerified;
import it.infn.mw.iam.api.account.password_reset.error.UserNotFoundError;
import it.infn.mw.iam.audit.events.account.password.PasswordResetEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.IamBCryptPasswordEncoder;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@ExtendWith(MockitoExtension.class)
class PasswordUpdateServiceTests {

  @Mock
  IamAccountRepository accountRepository;

  PasswordEncoder encoder = new BCryptPasswordEncoder();

  DefaultPasswordResetService updateService;

  @Mock
  ApplicationEventPublisher eventPublisher;

  @Mock
  IamAccountService accountService;

  private final String OLD_PASSWORD = "old";
  private final String NEW_PASSWORD = "new";

  @BeforeEach
  void init() {
    updateService =
        new DefaultPasswordResetService(accountRepository, null, null, encoder, accountService);
    updateService.setApplicationEventPublisher(eventPublisher);
  }

  private IamAccount newAccount(String username) {
    IamAccount result = new IamAccount();
    result.setUserInfo(new IamUserInfo());

    result.setUsername(username);
    result.setUuid(UUID.randomUUID().toString());
    return result;
  }

  @Test
  void rejectsOversizedPasswordWhenCalledWithoutBeanValidation() {
    IamAccount account = newAccount("active_user");
    account.setActive(true);
    account.getUserInfo().setEmailVerified(true);
    String originalHash = encoder.encode(OLD_PASSWORD);
    account.setPassword(originalHash);
    Mockito.when(accountRepository.findByUsername(account.getUsername()))
      .thenReturn(Optional.of(account));

    assertThrows(InvalidPasswordError.class,
        () -> updateService.updatePassword(account.getUsername(), OLD_PASSWORD, "é".repeat(37)));

    assertThat(account.getPassword(), is(originalHash));
    Mockito.verify(accountRepository, Mockito.never()).save(Mockito.any());
    Mockito.verifyNoInteractions(eventPublisher);
  }

  @Test
  void testUserIsNotActive() {

    final String USERNAME = "inactive_user";

    IamAccount account = newAccount(USERNAME);
    account.setActive(false);

    Mockito.when(accountRepository.findByUsername(anyString())).thenReturn(Optional.of(account));

    assertThrows(UserNotActiveOrNotVerified.class,
        () -> updateService.updatePassword(USERNAME, OLD_PASSWORD, NEW_PASSWORD));
  }

  @Test
  void testUserIsNotVerified() {

    final String USERNAME = "inactive_user";

    IamAccount account = newAccount(USERNAME);
    account.setActive(true);
    account.getUserInfo().setEmailVerified(false);

    Mockito.when(accountRepository.findByUsername(anyString())).thenReturn(Optional.of(account));

    assertThrows(UserNotActiveOrNotVerified.class,
        () -> updateService.updatePassword(USERNAME, OLD_PASSWORD, NEW_PASSWORD));

  }

  @Test
  void testUserNotFound() {

    final String USERNAME = "not_found_user";

    Mockito.when(accountRepository.findByUsername(anyString())).thenReturn(Optional.empty());

    assertThrows(UserNotFoundError.class,
        () -> updateService.updatePassword(USERNAME, OLD_PASSWORD, NEW_PASSWORD));
  }

  @Test
  void testBadUserPassword() {

    final String USERNAME = "active_user";
    final String BAD_OLD_PASSWORD = "bad_password";

    IamAccount account = newAccount(USERNAME);
    account.setActive(true);
    account.getUserInfo().setEmailVerified(true);
    account.setPassword(OLD_PASSWORD);

    Mockito.when(accountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));

    assertThrows(BadUserPasswordError.class,
        () -> updateService.updatePassword(USERNAME, BAD_OLD_PASSWORD, NEW_PASSWORD));

  }

  @Test
  void testUpdatePasswordWorks() {

    final String USERNAME = "active_user";

    IamAccount account = newAccount(USERNAME);
    account.setActive(true);
    account.getUserInfo().setEmailVerified(true);
    account.setPassword(encoder.encode(OLD_PASSWORD));

    Mockito.when(accountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));

    updateService.updatePassword(USERNAME, OLD_PASSWORD, NEW_PASSWORD);

    assertThat(encoder.matches(NEW_PASSWORD, account.getPassword()), is(true));

  }

  @Test
  void testPasswordResetClearsLoginLockout() {

    final String USERNAME = "locked_user";
    final String RESET_KEY = "reset-key";

    IamAccount account = newAccount(USERNAME);
    account.setActive(true);
    account.getUserInfo().setEmailVerified(true);
    account.setResetKey(RESET_KEY);

    Mockito.when(accountRepository.findByResetKey(RESET_KEY)).thenReturn(Optional.of(account));

    updateService.resetPassword(RESET_KEY, NEW_PASSWORD);

    assertThat(encoder.matches(NEW_PASSWORD, account.getPassword()), is(true));
    Mockito.verify(accountService).resetLoginLockout(Mockito.eq(account.getUuid()), Mockito.any());

  }

  @Test
  void resetRejectsOversizedPasswordWithoutConsumingTokenOrResettingLockout() {
    IamAccount account = newAccount("active_user");
    account.setActive(true);
    account.getUserInfo().setEmailVerified(true);
    account.setPassword(encoder.encode(OLD_PASSWORD));
    account.setResetKey("reset-token");
    String originalHash = account.getPassword();
    Mockito.when(accountRepository.findByResetKey("reset-token")).thenReturn(Optional.of(account));

    InvalidPasswordError error = assertThrows(InvalidPasswordError.class,
        () -> updateService.resetPassword("reset-token", "é".repeat(37)));

    assertEquals(IamBCryptPasswordEncoder.PASSWORD_TOO_LONG_MESSAGE, error.getMessage());
    assertEquals(originalHash, account.getPassword());
    assertEquals("reset-token", account.getResetKey());
    Mockito.verify(accountRepository, Mockito.never()).save(Mockito.any());
    Mockito.verifyNoInteractions(eventPublisher, accountService);

    // The same token still works with a password at the UTF-8 boundary.
    String boundary = "é".repeat(36);
    updateService.resetPassword("reset-token", boundary);

    assertTrue(encoder.matches(boundary, account.getPassword()));
    assertNull(account.getResetKey());
    Mockito.verify(accountRepository).save(account);
    Mockito.verify(accountService)
      .resetLoginLockout(account.getUuid(), LoginLockoutResetReason.PASSWORD_RESET);
    Mockito.verify(eventPublisher).publishEvent(Mockito.any(PasswordResetEvent.class));
  }

}
