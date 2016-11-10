package it.infn.mw.iam.api.account;

import java.util.NoSuchElementException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.notification.NotificationService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.TokenGenerator;

@Service
public class DefaultPasswordResetService implements PasswordResetService {

  private static final Logger logger = LoggerFactory.getLogger(DefaultPasswordResetService.class);

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private NotificationService notificationService;

  @Autowired
  private TokenGenerator tokenGenerator;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Override
  public void validateResetToken(String resetToken) {

    IamAccount account = accountRepository.findByResetKey(resetToken)
      .orElseThrow(() -> new InvalidPasswordResetTokenError(
          String.format("No account found for reset_key [%s]", resetToken)));

    if (!accountActiveAndEmailVerified(account)) {
      throw new InvalidPasswordResetTokenError(
          "The user account is not active or is linked to an email that has not been verified");
    }
  }

  @Override
  public void resetPassword(String resetToken, String password) {

    validateResetToken(resetToken);

    IamAccount account = accountRepository.findByResetKey(resetToken).get();

    account.setPassword(passwordEncoder.encode(password));
    account.setResetKey(null);

    accountRepository.save(account);
  }


  @Override
  public void createPasswordResetToken(String email) {
    try {
      IamAccount account = accountRepository.findByEmail(email).get();

      if (accountActiveAndEmailVerified(account)) {
        String resetKey = tokenGenerator.generateToken();
        account.setResetKey(resetKey);
        accountRepository.save(account);

        notificationService.createResetPasswordMessage(account);
      }
    } catch (NoSuchElementException nse) {
      logger.warn("No account found for the email {}. Message: {}", email, nse.getMessage());
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

    // set the new password
    account.setPassword(passwordEncoder.encode(newPassword));
    accountRepository.save(account);
  }

}
