package it.infn.mw.iam.api.account;

import java.util.NoSuchElementException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
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


  @Override
  public Boolean checkResetKey(String resetKey) {

    IamAccount account = accountRepository.findByResetKey(resetKey)
      .orElseThrow(() -> new ScimResourceNotFoundException(
          String.format("No account found for reset_key [%s]", resetKey)));

    return isAccountEnabled(account);
  }

  @Override
  public void changePassword(String resetKey, String password) {

    if (checkResetKey(resetKey)) {
      IamAccount account = accountRepository.findByResetKey(resetKey).get();
      // TODO: password digest?????
      account.setPassword(password);
      account.setResetKey(null);

      accountRepository.save(account);
    }
  }

  @Override
  public void forgotPassword(String email) {
    try {
      IamAccount account = accountRepository.findByEmail(email).get();

      if (isAccountEnabled(account)) {
        String resetKey = tokenGenerator.generateToken();
        account.setResetKey(resetKey);
        accountRepository.save(account);

        notificationService.createResetPasswordMessage(account);
      }
    } catch (NoSuchElementException nse) {
      logger.warn("No account found for the email {}. Message: {}", email, nse.getMessage());
    }
  }


  private boolean isAccountEnabled(IamAccount account) {
    return account.isActive() && (account.getUserInfo().getEmailVerified() != null
        && account.getUserInfo().getEmailVerified());
  }

}
