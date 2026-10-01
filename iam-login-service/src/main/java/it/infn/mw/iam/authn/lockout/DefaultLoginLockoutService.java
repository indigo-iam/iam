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

import java.time.Clock;
import java.util.Optional;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.LockedException;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LoginLockoutProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

public class DefaultLoginLockoutService implements LoginLockoutService {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultLoginLockoutService.class);

  private final Clock clock;
  private final IamAccountService accountService;
  private final IamAccountLoginLockoutRepository lockoutRepo;
  private final LoginLockoutProperties lockoutProperties;

  public DefaultLoginLockoutService(Clock clock, IamAccountService accountService,
      IamAccountLoginLockoutRepository lockoutRepo, IamProperties iamProperties) {
    this.clock = clock;
    this.accountService = accountService;
    this.lockoutRepo = lockoutRepo;
    this.lockoutProperties = iamProperties.getLoginLockout();
  }

  @PostConstruct
  public void validateConfiguration() {

    if (lockoutProperties.getMaxFailedAttemptsBeforeSuspension() < 1) {
      throw new IllegalStateException(
          "iam.login-lockout.max-failed-attempts-before-suspension must be >= 1. "
              + "Please provide the maximum number of failed login attempts allowed before suspension.");
    }

    if (lockoutProperties.getSuspensionDurationMinutes() < 1) {
      throw new IllegalStateException("iam.login-lockout.suspension-duration-minutes must be >= 1. "
          + "Please provide the suspension duration in minutes.");
    }

    if (lockoutProperties.isDisableAfterMaxSuspensionRounds()
        && lockoutProperties.getMaxSuspensionRounds() < 1) {
      throw new IllegalStateException("iam.login-lockout.max-suspension-rounds must be >= 1 when "
          + "iam.login-lockout.disable-after-max-suspension-rounds is true. "
          + "Please provide the maximum number of suspension rounds allowed before the account is permanently disabled.");
    }

    LOG.info("[LOGIN-LOCKOUT] IAM Account Login lockout enabled");
  }

  @Override
  @Transactional(readOnly = true)
  public void checkIamAccountLockout(String username) {

    lockoutRepo.findByAccountUsername(username).ifPresent(lockout -> {
      if (isSuspended(lockout)) {
        throw new LockedException("Bad credentials");
      }
    });
  }

  @Override
  @Transactional
  public void recordFailedAttempt(String username) {

    Optional<IamAccount> maybeAccount =
        accountService.findByUsernameForUpdate(username);

    if (maybeAccount.isEmpty()) {
      return;
    }

    IamAccount account = maybeAccount.get();

    if (!account.isActive()) {
      return;
    }

    IamAccountLoginLockout lockout = lockoutRepo.findByAccountUsername(username)
      .orElseGet(() -> new IamAccountLoginLockout(account));

    if (isSuspended(lockout)) {
      return;
    }

    if (isExpired(lockout)) {
      accountService.unsuspendAccount(account);
    }

    accountService.loginFailedAttempt(account);
    lockout = account.getLockoutInfo();

    if (lockout.getFailedAttempts() < lockoutProperties.getMaxFailedAttemptsBeforeSuspension()) {
      return;
    }

    lockout.setLockoutCount(lockout.getLockoutCount() + 1);
    lockoutRepo.save(lockout);

    accountService.suspendAccount(account);

    if (lockoutProperties.isDisableAfterMaxSuspensionRounds()
        && lockout.getLockoutCount() > lockoutProperties.getMaxSuspensionRounds()) {

      accountService.disableAccount(account);
    }
  }

  @Override
  @Transactional
  public void resetFailedAttempts(String username) {

    accountService.findByUsernameForUpdate(username).ifPresent(account -> {
      accountService.unsuspendAccount(account);
    });
  }

  @Override
  @Transactional
  public void adminRevokeLockout(String accountUuid) {

    lockoutRepo.findByAccountUuid(accountUuid).ifPresent(lockout -> {
      accountService.unsuspendAccount(lockout.getAccount());
    });
  }

  private boolean isSuspended(IamAccountLoginLockout lockout) {
    return lockout.getSuspendedUntil() != null
        && clock.instant().isBefore(lockout.getSuspendedUntil().toInstant());
  }

  private boolean isExpired(IamAccountLoginLockout lockout) {
    return lockout.getSuspendedUntil() != null
        && clock.instant().isAfter(lockout.getSuspendedUntil().toInstant());
  }
}
