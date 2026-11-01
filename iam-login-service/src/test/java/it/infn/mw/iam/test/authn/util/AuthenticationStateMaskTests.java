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
package it.infn.mw.iam.test.authn.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import java.util.concurrent.Callable;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.infn.mw.iam.authn.util.AuthenticationStateMask;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;

class AuthenticationStateMaskTests {

  @Test
  void checkLoginAllowedMasksDisabled() {
    IamAccountService svc = mock(IamAccountService.class);
    doThrow(new DisabledException("disabled")).when(svc).checkLoginAllowed("uuid");

    BadCredentialsException ex = assertThrows(BadCredentialsException.class,
        () -> AuthenticationStateMask.checkLoginAllowedOrThrowBadCredentials(svc, "uuid", "Bad credentials"));
    assertEquals(DisabledException.class, ex.getCause().getClass());
  }

  @Test
  void checkLoginAllowedMasksLocked() {
    IamAccountService svc = mock(IamAccountService.class);
    doThrow(new LockedException("locked")).when(svc).checkLoginAllowed("uuid");

    BadCredentialsException ex = assertThrows(BadCredentialsException.class,
        () -> AuthenticationStateMask.checkLoginAllowedOrThrowBadCredentials(svc, "uuid", "Bad credentials"));
    assertEquals(LockedException.class, ex.getCause().getClass());
  }

  @Test
  void checkLoginAllowedMasksUsernameNotFound() {
    IamAccountService svc = mock(IamAccountService.class);
    doThrow(new UsernameNotFoundException("missing")).when(svc).checkLoginAllowed("uuid");

    BadCredentialsException ex = assertThrows(BadCredentialsException.class,
        () -> AuthenticationStateMask.checkLoginAllowedOrThrowBadCredentials(svc, "uuid", "Bad credentials"));
    assertEquals(UsernameNotFoundException.class, ex.getCause().getClass());
  }

  @Test
  void resetLoginLockoutMasksExceptions() {
    IamAccountService svc = mock(IamAccountService.class);
    doThrow(new LockedException("locked")).when(svc).resetLoginLockout("uuid", LoginLockoutResetReason.ADMIN_REVOKE);

    BadCredentialsException ex = assertThrows(BadCredentialsException.class,
        () -> AuthenticationStateMask.resetLoginLockoutOrThrowBadCredentials(svc, "uuid",
            LoginLockoutResetReason.ADMIN_REVOKE, "Bad credentials"));
    assertEquals(LockedException.class, ex.getCause().getClass());
  }

  @Test
  void callWithMaskedAccountStateMasksExpectedExceptions() {
    Callable<Void> action = () -> { throw new DisabledException("disabled"); };
    BadCredentialsException ex = assertThrows(BadCredentialsException.class,
        () -> AuthenticationStateMask.callWithMaskedAccountState(action, "Bad credentials"));
    assertEquals(DisabledException.class, ex.getCause().getClass());
  }

  @Test
  void callWithMaskedAccountStatePropagatesOtherExceptions() {
    Callable<Void> action = () -> { throw new IllegalStateException("boom"); };
    assertThrows(IllegalStateException.class,
        () -> AuthenticationStateMask.callWithMaskedAccountState(action, "Bad credentials"));
  }
}