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
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import it.infn.mw.iam.api.account.password_reset.error.UserNotActiveOrNotVerified;
import it.infn.mw.iam.api.account.password_reset.error.UserNotFoundError;
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

  private final String OLD_PASSWORD = "old";
  private final String NEW_PASSWORD = "new";

  @BeforeEach
  void init() {
    updateService = new DefaultPasswordResetService(accountRepository, null, null, encoder);
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
    final String OLD_PASSWORD = "password";
    final String BAD_OLD_PASSWORD = "bad_password";
    final String NEW_PASSWORD = "new_password";

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
    final String OLD_PASSWORD = "password";
    final String NEW_PASSWORD = "new_password";

    IamAccount account = newAccount(USERNAME);
    account.setActive(true);
    account.getUserInfo().setEmailVerified(true);
    account.setPassword(encoder.encode(OLD_PASSWORD));

    Mockito.when(accountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));

    updateService.updatePassword(USERNAME, OLD_PASSWORD, NEW_PASSWORD);

    assertThat(encoder.matches(NEW_PASSWORD, account.getPassword()), is(true));

  }
}
