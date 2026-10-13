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
package it.infn.mw.iam.api.account.password_reset;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.account.password_reset.error.BadUserPasswordError;
import it.infn.mw.iam.api.account.password_reset.error.InvalidPasswordResetTokenError;
import it.infn.mw.iam.api.account.password_reset.error.UserNotActiveOrNotVerified;
import it.infn.mw.iam.api.account.password_reset.error.UserNotFoundError;
import it.infn.mw.iam.audit.events.account.password.PasswordResetEvent;
import it.infn.mw.iam.audit.events.account.password.PasswordUpdatedEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.TokenGenerator;

@Service
public class DefaultPasswordResetService
    implements PasswordResetService, ApplicationEventPublisherAware {

  private static final Logger logger = LoggerFactory.getLogger(DefaultPasswordResetService.class);

  private final IamAccountRepository accountRepository;
  private final NotificationFactory notificationFactory;
  private final TokenGenerator tokenGenerator;
  private final PasswordEncoder passwordEncoder;
  private final IamAccountService accountService;
  private ApplicationEventPublisher eventPublisher;

  public DefaultPasswordResetService(IamAccountRepository accountRepository,
      NotificationFactory notificationFactory, TokenGenerator tokenGenerator,
      PasswordEncoder passwordEncoder, IamAccountService accountService) {

    this.accountRepository = accountRepository;
    this.notificationFactory = notificationFactory;
    this.tokenGenerator = tokenGenerator;
    this.passwordEncoder = passwordEncoder;
    this.accountService = accountService;
  }

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  private IamAccount findAndValidateAccount(String resetToken) {

    IamAccount account = accountRepository.findByResetKey(resetToken)
      .orElseThrow(() -> new InvalidPasswordResetTokenError(
          String.format("No account found for reset_key [%s]", resetToken)));

    if (!accountActiveAndEmailVerified(account)) {
      throw new InvalidPasswordResetTokenError(
          "The user account is not active or is linked to an email that has not been verified");
    }

    return account;
  }

  @Override
  public void validateResetToken(String resetToken) {

    findAndValidateAccount(resetToken);
  }

  @Override
  public void resetPassword(String resetToken, String password) {

    IamAccount account = findAndValidateAccount(resetToken);

    account.setPassword(passwordEncoder.encode(password));
    account.setResetKey(null);

    accountRepository.save(account);

    accountService.resetLoginLockout(account.getUuid(), LoginLockoutResetReason.PASSWORD_RESET);

    eventPublisher.publishEvent(new PasswordResetEvent(this, account,
        String.format("User %s reset its password", account.getUsername())));
  }

  @Override
  public void createPasswordResetToken(String email) {
    Optional<IamAccount> accountByMail = accountRepository.findByEmail(email);

    accountByMail.ifPresent(a -> {
      if (accountActiveAndEmailVerified(a)) {
        String resetKey = tokenGenerator.generateToken();
        a.setResetKey(resetKey);
        accountRepository.save(a);
        notificationFactory.createResetPasswordMessage(a);
      }
    });

    if (!accountByMail.isPresent()) {
      logger.warn("No account found linked to email: {}", email);
    }
  }

  private boolean accountActiveAndEmailVerified(IamAccount account) {
    return account.isActive() && (account.getUserInfo().getEmailVerified() != null
        && account.getUserInfo().getEmailVerified());
  }

  @Override
  public void updatePassword(String username, String oldPassword, String newPassword)
      throws UserNotActiveOrNotVerified, BadUserPasswordError {

    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> new UserNotFoundError("No user found linked to username " + username));

    if (!accountActiveAndEmailVerified(account)) {
      throw new UserNotActiveOrNotVerified("Account is not active or email is not verified");
    }

    if (!passwordEncoder.matches(oldPassword, account.getPassword())) {
      throw new BadUserPasswordError("Wrong password provided");
    }

    account.setPassword(passwordEncoder.encode(newPassword));
    accountRepository.save(account);

    eventPublisher.publishEvent(new PasswordUpdatedEvent(this, account,
        String.format("User %s update its password", account.getUsername())));
  }

}
