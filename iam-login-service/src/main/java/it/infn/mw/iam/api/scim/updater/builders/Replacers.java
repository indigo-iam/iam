package it.infn.mw.iam.api.scim.updater.builders;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_ACTIVE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_EMAIL;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_FAMILY_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_GIVEN_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PASSWORD;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_USERNAME;

import java.util.function.Consumer;
import java.util.function.Predicate;

import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.DefaultAccountUpdater;
import it.infn.mw.iam.api.scim.updater.util.AccountFinder;
import it.infn.mw.iam.api.scim.updater.util.IdNotBoundChecker;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class Replacers extends AccountBuilderSupport {

  final Predicate<String> emailAddChecks;
  final Predicate<String> usernameAddChecks;

  final Consumer<String> encodedPasswordSetter;
  final Predicate<String> encodedPasswordChecker;

  final AccountFinder<String> findByEmail;
  final AccountFinder<String> findByUsername;

  public Replacers(IamAccountRepository repo, PasswordEncoder encoder, IamAccount account) {

    super(repo, encoder, account);
    findByEmail = e -> repo.findByEmail(e);
    findByUsername = u -> repo.findByUsername(u);
    encodedPasswordSetter = t -> account.setPassword(encoder.encode(t));
    encodedPasswordChecker = t -> !encoder.matches(t, account.getPassword());
    emailAddChecks = buildEmailAddChecks();
    usernameAddChecks = buildUsernameAddChecks();

  }

  private Predicate<String> buildEmailAddChecks() {
    Predicate<String> emailNotBound =
        new IdNotBoundChecker<String>(findByEmail, account, (e, a) -> {
          throw new ScimResourceExistsException("Email " + e + " already bound to another user");
        });

    Predicate<String> emailNotOwned = e -> !account.getUserInfo().getEmail().equals(e);

    return emailNotBound.and(emailNotOwned);
  }

  private Predicate<String> buildUsernameAddChecks() {
    Predicate<String> usernameNotBound =
        new IdNotBoundChecker<String>(findByUsername, account, (e, a) -> {
          throw new ScimResourceExistsException("Username " + e + " already bound to another user");
        });

    Predicate<String> usernameNotOwned = e -> !account.getUsername().equals(e);

    return usernameNotBound.and(usernameNotOwned);
  }

  public AccountUpdater givenName(String givenName) {

    IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String>(account, ACCOUNT_REPLACE_GIVEN_NAME, ui::getGivenName,
        ui::setGivenName, givenName);
  }

  public AccountUpdater familyName(String familyName) {
    final IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String>(account, ACCOUNT_REPLACE_FAMILY_NAME, ui::getFamilyName,
        ui::setFamilyName, familyName);
  }

  public AccountUpdater picture(String newPicture) {

    final IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String>(account, ACCOUNT_REPLACE_PICTURE, ui::getPicture, ui::setPicture,
        newPicture);

  }

  public AccountUpdater email(String email) {
    final IamUserInfo ui = account.getUserInfo();

    return new DefaultAccountUpdater<String>(account, ACCOUNT_REPLACE_EMAIL, ui::setEmail, email, emailAddChecks);
  }

  public AccountUpdater password(String newPassword) {

    return new DefaultAccountUpdater<String>(account, ACCOUNT_REPLACE_PASSWORD, encodedPasswordSetter, newPassword,
        encodedPasswordChecker);
  }

  public AccountUpdater username(String newUsername) {

    return new DefaultAccountUpdater<String>(account, ACCOUNT_REPLACE_USERNAME, account::setUsername, newUsername,
        usernameAddChecks);
  }

  public AccountUpdater active(boolean isActive) {

    return new DefaultAccountUpdater<Boolean>(account, ACCOUNT_REPLACE_ACTIVE, account::isActive,
        account::setActive, isActive);
  }

}
