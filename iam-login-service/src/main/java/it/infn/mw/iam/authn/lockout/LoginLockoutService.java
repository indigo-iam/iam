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
package it.infn.mw.iam.authn.lockout;

/**
 * Tracks failed login attempts and enforces temporary suspensions
 *  and permanent account disabling, if `disable-after-max-suspension-rounds` enabled.
 *
 * Password failures and TOTP failures share the same counter. The lifecycle:
 *
 * User fails {max-failed-attempts-before-suspension} times => suspended for
 * {suspension-duration-minutes}.
 * Suspension expires => counter resets, user gets another round of attempts.
 * If {disable-after-max-suspension-rounds} is true:
 *   after {max-suspension-rounds} suspension rounds the account is disabled.
 * If false (default): the account is never disabled, only repeatedly suspended.
 * An admin can clear a lockout at any time.
 */
public interface LoginLockoutService {

  /**
   * Throws {@link org.springframework.security.authentication.LockedException} if the account
   * is currently suspended. If a previous suspension has expired, silently resets the attempt
   * counter for a fresh round.
   *
   * The exception message is internal only: callers translate it to the same generic
   * bad-credentials failure returned for any other failed login, to prevent account
   * enumeration. The account owner is notified of the lockout by email.
   */
  void checkIamAccountLockout(String username);

  /**
   * Records a single failed attempt (password or TOTP). When the attempt count reaches the
   * threshold the account is suspended. When all suspension rounds are exhausted and
   * disable-after-max-suspension-rounds is true, the account is disabled and the lockout row is deleted.
   */
  void recordFailedAttempt(String username);

  /**
   * Deletes the lockout row for the given username. Called after a fully successful
   * authentication (password-only login, or TOTP verification).
   */
  void resetFailedAttempts(String username);

  /**
   * Admin-triggered unlock. Deletes the lockout row for the given account,
   * clearing any active suspension.
   */
  void adminRevokeLockout(String accountUuid);
}
