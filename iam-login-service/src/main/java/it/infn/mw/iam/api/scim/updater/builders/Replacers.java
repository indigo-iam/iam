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
package it.infn.mw.iam.api.scim.updater.builders;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_ACTIVE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_SERVICE_ACCOUNT;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_EMAIL;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_FAMILY_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_GIVEN_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PASSWORD;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_USERNAME;

import java.util.function.Consumer;
import java.util.function.Predicate;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.DefaultAccountUpdater;
import it.infn.mw.iam.api.scim.updater.UsernameUpdater;
import it.infn.mw.iam.api.scim.updater.util.AccountFinder;
import it.infn.mw.iam.api.scim.updater.util.IdNotBoundChecker;
import it.infn.mw.iam.audit.events.account.ActiveReplacedEvent;
import it.infn.mw.iam.audit.events.account.ServiceAccountReplacedEvent;
import it.infn.mw.iam.audit.events.account.EmailReplacedEvent;
import it.infn.mw.iam.audit.events.account.FamilyNameReplacedEvent;
import it.infn.mw.iam.audit.events.account.GivenNameReplacedEvent;
import it.infn.mw.iam.audit.events.account.PasswordReplacedEvent;
import it.infn.mw.iam.audit.events.account.PictureReplacedEvent;
import it.infn.mw.iam.audit.events.account.UsernameReplacedEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;

public class Replacers extends AccountBuilderSupport {

  final Predicate<String> emailAddChecks;
  final Predicate<String> usernameAddChecks;

  final Consumer<String> encodedPasswordSetter;
  final Predicate<String> encodedPasswordChecker;

  final AccountFinder<String> findByEmail;
  final AccountFinder<String> findByUsername;

  public Replacers(IamAccountRepository repo, IamAccountService accountService,
      PasswordEncoder encoder, IamAccount account, OAuth2TokenEntityService tokenService,
      UsernameValidator usernameValidator) {

    super(repo, accountService, tokenService, encoder, usernameValidator, account);
    findByEmail = repo::findByEmail;
    findByUsername = repo::findByUsername;
    encodedPasswordSetter = t -> account.setPassword(encoder.encode(t));
    encodedPasswordChecker = t -> !encoder.matches(t, account.getPassword());
    emailAddChecks = buildEmailAddChecks();
    usernameAddChecks = buildUsernameAddChecks();

  }

  private Predicate<String> buildEmailAddChecks() {
    Predicate<String> emailNotBound =
        new IdNotBoundChecker<>(findByEmail, account, (e, a) -> {
          throw new ScimResourceExistsException("Email " + e + " already bound to another user");
        });

    Predicate<String> emailNotOwned = e -> !account.getUserInfo().getEmail().equals(e);

    return emailNotBound.and(emailNotOwned);
  }

  private Predicate<String> buildUsernameAddChecks() {
    Predicate<String> usernameNotBound =
        new IdNotBoundChecker<>(findByUsername, account, (e, a) -> {
          throw new ScimResourceExistsException("Username " + e + " already bound to another user");
        });

    Predicate<String> usernameNotOwned = e -> !account.getUsername().equals(e);

    Predicate<String> usernameNotUnix = e -> usernameValidator.isValid(e, null);

    return usernameNotBound.and(usernameNotOwned).and(usernameNotUnix);
  }

  public AccountUpdater givenName(String givenName) {

    IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String, GivenNameReplacedEvent>(account,
        ACCOUNT_REPLACE_GIVEN_NAME, ui::getGivenName, ui::setGivenName, givenName,
        GivenNameReplacedEvent::new);
  }

  public AccountUpdater familyName(String familyName) {
    final IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String, FamilyNameReplacedEvent>(account,
        ACCOUNT_REPLACE_FAMILY_NAME, ui::getFamilyName, ui::setFamilyName, familyName,
        FamilyNameReplacedEvent::new);
  }

  public AccountUpdater picture(String newPicture) {

    final IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String, PictureReplacedEvent>(account, ACCOUNT_REPLACE_PICTURE,
        ui::getPicture, ui::setPicture, newPicture, PictureReplacedEvent::new);

  }

  public AccountUpdater email(String email) {
    final IamUserInfo ui = account.getUserInfo();

    return new DefaultAccountUpdater<String, EmailReplacedEvent>(account, ACCOUNT_REPLACE_EMAIL,
        ui::setEmail, email, emailAddChecks, EmailReplacedEvent::new);
  }

  public AccountUpdater password(String newPassword) {

    return new DefaultAccountUpdater<String, PasswordReplacedEvent>(account,
        ACCOUNT_REPLACE_PASSWORD, encodedPasswordSetter, newPassword, encodedPasswordChecker,
        PasswordReplacedEvent::new);
  }

  public AccountUpdater username(String newUsername) {

    return new UsernameUpdater(account, ACCOUNT_REPLACE_USERNAME, account::setUsername, newUsername,
        usernameAddChecks, UsernameReplacedEvent::new, tokenService);
  }

  public AccountUpdater active(boolean isActive) {

    return new DefaultAccountUpdater<Boolean, ActiveReplacedEvent>(account, ACCOUNT_REPLACE_ACTIVE,
        account::isActive, account::setActive, isActive, ActiveReplacedEvent::new);
  }

  public AccountUpdater serviceAccount(boolean isServiceAccount) {
    return new DefaultAccountUpdater<Boolean, ServiceAccountReplacedEvent>(account, ACCOUNT_REPLACE_SERVICE_ACCOUNT,
        account::isServiceAccount, account::setServiceAccount, isServiceAccount, ServiceAccountReplacedEvent::new);
  }

}
