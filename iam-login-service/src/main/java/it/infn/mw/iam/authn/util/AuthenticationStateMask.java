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
package it.infn.mw.iam.authn.util;

import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;

/**
 * Small helpers to mask account-state exceptions behind generic authentication failures.
 */
public final class AuthenticationStateMask {

  private static final Logger LOG = LoggerFactory.getLogger(AuthenticationStateMask.class);

  private AuthenticationStateMask() {}

  public static void checkLoginAllowedOrThrowBadCredentials(IamAccountService svc,
      String accountUuid, String badMessage) {
    try {
      svc.checkLoginAllowed(accountUuid);
    } catch (DisabledException | LockedException | UsernameNotFoundException e) {
      LOG.debug("Masking account-state exception for account {}: {}", accountUuid, e.getMessage(),
          e);
      throw new BadCredentialsException(badMessage, e);
    }
  }

  public static void resetLoginLockoutOrThrowBadCredentials(IamAccountService svc,
      String accountUuid, LoginLockoutResetReason reason, String badMessage) {
    try {
      svc.resetLoginLockout(accountUuid, reason);
    } catch (DisabledException | LockedException | UsernameNotFoundException e) {
      LOG.debug("Masking account-state exception during reset for account {}: {}", accountUuid,
          e.getMessage(), e);
      throw new BadCredentialsException(badMessage, e);
    }
  }

  public static <T> T callWithMaskedAccountState(Callable<T> action, String badMessage) {
    try {
      return action.call();
    } catch (DisabledException | LockedException | UsernameNotFoundException e) {
      LOG.debug("Masking account-state exception: {}", e.getMessage(), e);
      throw new BadCredentialsException(badMessage, e);
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      // wrap checked exceptions we don't expect
      throw new RuntimeException(e);
    }
  }
}
