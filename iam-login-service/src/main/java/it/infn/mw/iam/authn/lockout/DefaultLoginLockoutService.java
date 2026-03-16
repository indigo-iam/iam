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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LoginLockoutProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

@Service
public class DefaultLoginLockoutService implements LoginLockoutService {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultLoginLockoutService.class);

  private final IamAccountLoginLockoutRepository lockoutRepo;
  private final IamAccountRepository accountRepo;
  private final LoginLockoutProperties properties;

  public DefaultLoginLockoutService(IamAccountLoginLockoutRepository lockoutRepo,
      IamAccountRepository accountRepo, IamProperties iamProperties) {
    this.lockoutRepo = lockoutRepo;
    this.accountRepo = accountRepo;
    this.properties = iamProperties.getLoginLockout();
  }

  @PostConstruct
  void validateConfiguration() {
    if (!properties.isEnabled()) {
      LOG.info("Iam Account Login lockout feature is disabled");
      return;
    }

    if (properties.getMaxFailedAttempts() < 1) {
      throw new IllegalStateException(
          "iam.login-lockout.max-failed-attempts must be >= 1. "
              + "Please provide the maximum number of failed login attempts allowed before suspension.");
    }

    if (properties.getLockoutMinutes() < 1) {
      throw new IllegalStateException(
          "iam.login-lockout.lockout-minutes must be >= 1. "
              + "Please provide the suspension duration in minutes.");
    }

    if (properties.isDisableAfterMaxFailures() && properties.getMaxConcurrentFailures() < 1) {
      throw new IllegalStateException(
          "iam.login-lockout.max-concurrent-failures must be >= 1 when disable-after-max-failures is true. "
              + "Please provide the maximum number of suspension rounds allowed before the account is permanently disabled.");
    }

    LOG.info("Iam Account Login lockout enabled: max-failed-attempts={}, lockout-minutes={}, "
        + "max-concurrent-failures={}, disable-after-max-failures={}",
        properties.getMaxFailedAttempts(), properties.getLockoutMinutes(),
        properties.getMaxConcurrentFailures(), properties.isDisableAfterMaxFailures());
  }

  @Override
  @Transactional
  public void checkIamAccountLockout(String username) {

    if (!properties.isEnabled()) {
      return;
    }

    Optional<IamAccountLoginLockout> lockoutOpt = lockoutRepo.findByAccountUsername(username);

    if (lockoutOpt.isEmpty()) {
      return;
    }

    IamAccountLoginLockout lockout = lockoutOpt.get();

    if (isSuspended(lockout)) {
      LOG.info("Login blocked: account '{}' is suspended until {}", username,
          lockout.getSuspendedUntil());
      throw new LockedException(
          "Account is temporarily suspended. Please try again later or contact support for assistance.");
    }

    // Previous suspension has expired; reset the attempt counter for a fresh round
    if (lockout.getSuspendedUntil() != null) {
      LOG.debug("Suspension for '{}' has expired, starting fresh round", username);
      lockout.setFailedAttempts(0);
      lockout.setFirstFailureTime(null);
      lockout.setSuspendedUntil(null);
      lockoutRepo.save(lockout);
    }
  }

  @Override
  @Transactional
  public void recordFailedAttempt(String username) {

    if (!properties.isEnabled()) {
      return;
    }

    Optional<IamAccount> accountOpt = accountRepo.findByUsername(username);

    if (accountOpt.isEmpty()) {
      return;
    }

    IamAccount account = accountOpt.get();

    if (!account.isActive()) {
      return;
    }

    IamAccountLoginLockout lockout = lockoutRepo.findByAccountUsername(username)
        .orElseGet(() -> new IamAccountLoginLockout(account));

    if (isSuspended(lockout)) {
      return;
    }

    // if a previous suspension has expired but checkIamAccountLockout was not called,
    // reset the counter so we don't carry over stale failedAttempts from the prior round.
    if (lockout.getSuspendedUntil() != null) {
      lockout.setFailedAttempts(0);
      lockout.setFirstFailureTime(null);
      lockout.setSuspendedUntil(null);
    }

    Instant now = Instant.now();

    if (lockout.getFailedAttempts() == 0) {
      lockout.setFirstFailureTime(Date.from(now));
    }

    lockout.setFailedAttempts(lockout.getFailedAttempts() + 1);

    LOG.info("Failed login attempt {} of {} for account '{}'", lockout.getFailedAttempts(),
        properties.getMaxFailedAttempts(), username);

    if (lockout.getFailedAttempts() >= properties.getMaxFailedAttempts()) {

      lockout.setLockoutCount(lockout.getLockoutCount() + 1);

      if (properties.isDisableAfterMaxFailures()
          && lockout.getLockoutCount() > properties.getMaxConcurrentFailures()) {
        // All suspension rounds exhausted; disable the account and clean up
        account.setActive(false);
        accountRepo.save(account);
        lockoutRepo.delete(lockout);
        LOG.warn("Account '{}' disabled after {} suspension rounds", username,
            properties.getMaxConcurrentFailures());
        return;
      }

      // Suspend for the configured duration
      Instant suspendUntil = now.plus(properties.getLockoutMinutes(), ChronoUnit.MINUTES);
      lockout.setSuspendedUntil(Date.from(suspendUntil));

      LOG.warn("Account '{}' suspended until {} (round {} of {})", username,
          lockout.getSuspendedUntil(), lockout.getLockoutCount(),
          properties.getMaxConcurrentFailures());
    }

    lockoutRepo.save(lockout);
  }

  @Override
  @Transactional
  public void resetFailedAttempts(String username) {

    if (!properties.isEnabled()) {
      return;
    }

    lockoutRepo.findByAccountUsername(username).ifPresent(lockout -> {
      lockoutRepo.delete(lockout);
      LOG.debug("Lockout record deleted for account '{}'", username);
    });
  }

  @Override
  @Transactional
  public void adminRevokeLockout(String accountUuid) {

    lockoutRepo.findByAccountUuid(accountUuid).ifPresent(lockout -> {
      lockoutRepo.delete(lockout);
      LOG.info("Admin revoked suspension for account '{}'", lockout.getAccount().getUsername());
    });
  }

  private boolean isSuspended(IamAccountLoginLockout lockout) {
    return lockout.getSuspendedUntil() != null
        && Instant.now().isBefore(lockout.getSuspendedUntil().toInstant());
  }
}
