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
package it.infn.mw.iam.api.scim.updater.factory;

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.add;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.remove;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.replace;

import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.converter.OidcIdConverter;
import it.infn.mw.iam.api.scim.converter.SamlIdConverter;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.AccountUpdaterBuilder;
import it.infn.mw.iam.api.scim.updater.AccountUpdaterFactory;
import it.infn.mw.iam.api.scim.updater.builders.AccountUpdaters;
import it.infn.mw.iam.api.scim.updater.builders.Adders;
import it.infn.mw.iam.api.scim.updater.builders.Removers;
import it.infn.mw.iam.api.scim.updater.builders.Replacers;
import it.infn.mw.iam.api.scim.updater.util.CollectionHelpers;
import it.infn.mw.iam.api.scim.updater.util.ScimCollectionConverter;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;

public class DefaultAccountUpdaterFactory implements AccountUpdaterFactory<IamAccount, ScimUser> {

  final PasswordEncoder encoder;

  final IamAccountRepository repo;
  final IamAccountService accountService;
  final OAuth2TokenEntityService tokenService;

  final UsernameValidator usernameValidator;

  final OidcIdConverter oidcIdConverter;
  final SamlIdConverter samlIdConverter;
  final SshKeyConverter sshKeyConverter;
  final X509CertificateConverter x509CertificateConverter;

  public DefaultAccountUpdaterFactory(PasswordEncoder encoder, IamAccountRepository repo,
      IamAccountService accountService, OAuth2TokenEntityService tokenService,
      OidcIdConverter oidcIdConverter, SamlIdConverter samlIdConverter,
      SshKeyConverter sshKeyConverter, X509CertificateConverter x509CertificateConverter,
      UsernameValidator usernameValidator) {

    this.accountService = accountService;
    this.tokenService = tokenService;
    this.encoder = encoder;
    this.repo = repo;
    this.oidcIdConverter = oidcIdConverter;
    this.samlIdConverter = samlIdConverter;
    this.sshKeyConverter = sshKeyConverter;
    this.x509CertificateConverter = x509CertificateConverter;
    this.usernameValidator = usernameValidator;
  }

  private ScimCollectionConverter<IamSshKey, ScimSshKey> sshKeyConverter(ScimUser user) {

    return new ScimCollectionConverter<>(user.getIndigoUser()::getSshKeys,
        sshKeyConverter::entityFromDto);
  }

  private ScimCollectionConverter<IamOidcId, ScimOidcId> oidcIdConverter(ScimUser user) {
    return new ScimCollectionConverter<>(user.getIndigoUser()::getOidcIds,
        oidcIdConverter::entityFromDto);
  }

  private ScimCollectionConverter<IamSamlId, ScimSamlId> samlIdConverter(ScimUser user) {
    return new ScimCollectionConverter<>(user.getIndigoUser()::getSamlIds,
        samlIdConverter::entityFromDto);
  }

  private ScimCollectionConverter<IamX509Certificate, ScimX509Certificate> x509CertificateConverter(
      ScimUser user) {
    return new ScimCollectionConverter<>(
        user.getIndigoUser()::getCertificates, x509CertificateConverter::entityFromDto);
  }

  private static <T> AccountUpdater buildUpdater(AccountUpdaterBuilder<T> factory,
      T value) {
    return factory.build(value);
  }

  private static <T> void addUpdater(List<AccountUpdater> updaters, Predicate<T> valuePredicate,
      Supplier<T> valueSupplier, AccountUpdaterBuilder<T> factory) {

    T value = valueSupplier.get();
    if (valuePredicate.test(value)) {
      updaters.add(buildUpdater(factory, value));
    }
  }

  private void prepareAdders(List<AccountUpdater> updaters, ScimUser user, IamAccount account) {

    Adders add = AccountUpdaters.adders(repo, accountService, encoder, account, tokenService, usernameValidator);

    if (user.hasName()) {

      addUpdater(updaters, Objects::nonNull, user.getName()::getGivenName, add::givenName);
      addUpdater(updaters, Objects::nonNull, user.getName()::getFamilyName, add::familyName);
    }

    addUpdater(updaters, Objects::nonNull, user::getUserName, add::username);
    addUpdater(updaters, Objects::nonNull, user::getPassword, add::password);
    addUpdater(updaters, Objects::nonNull, user::getActive, add::active);

    if (user.hasEmails()) {
      addUpdater(updaters, Objects::nonNull, user.getEmails().get(0)::getValue, add::email);
    }

    if (user.hasPhotos()) {
      addUpdater(updaters, Objects::nonNull, user.getPhotos().get(0)::getValue, add::picture);
    }

    if (user.hasOidcIds()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, oidcIdConverter(user), add::oidcId);
    }

    if (user.hasSamlIds()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, samlIdConverter(user), add::samlId);
    }

    if (user.hasSshKeys()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, sshKeyConverter(user), add::sshKey);
    }

    if (user.hasX509Certificates()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, x509CertificateConverter(user),
          add::x509Certificate);
    }
  }

  private void prepareRemovers(List<AccountUpdater> updaters, ScimUser user, IamAccount account) {
    Removers remove = AccountUpdaters.removers(repo, accountService, account);

    if (user.hasOidcIds()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, oidcIdConverter(user),
          remove::oidcId);
    }

    if (user.hasSamlIds()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, samlIdConverter(user),
          remove::samlId);
    }

    if (user.hasSshKeys()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, sshKeyConverter(user),
          remove::sshKey);
    }

    if (user.hasX509Certificates()) {
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, x509CertificateConverter(user),
          remove::x509Certificate);
    }

    if (user.hasPhotos()) {
      addUpdater(updaters, Objects::nonNull, user.getPhotos().get(0)::getValue, remove::picture);
    }
  }

  private void prepareReplacers(List<AccountUpdater> updaters, ScimUser user, IamAccount account) {

    Replacers replace = AccountUpdaters.replacers(repo, accountService, encoder, account,
        tokenService, usernameValidator);

    if (user.hasName()) {
      addUpdater(updaters, Objects::nonNull, user.getName()::getGivenName, replace::givenName);
      addUpdater(updaters, Objects::nonNull, user.getName()::getFamilyName, replace::familyName);
    }

    addUpdater(updaters, Objects::nonNull, user::getUserName, replace::username);
    addUpdater(updaters, Objects::nonNull, user::getPassword, replace::password);
    addUpdater(updaters, Objects::nonNull, user::getActive, replace::active);

    if (user.hasEmails()) {
      addUpdater(updaters, Objects::nonNull, user.getEmails().get(0)::getValue, replace::email);
    }

    if (user.hasPhotos()) {
      addUpdater(updaters, Objects::nonNull, user.getPhotos().get(0)::getValue, replace::picture);
    }
  }

  @Override
  public List<AccountUpdater> getUpdatersForPatchOperation(IamAccount account,
      ScimPatchOperation<ScimUser> op) throws ScimPatchOperationNotSupported {

    final List<AccountUpdater> updaters = Lists.newArrayList();

    final ScimUser user = op.getValue();

    if (op.getOp().equals(add)) {

      prepareAdders(updaters, user, account);

    }
    if (op.getOp().equals(remove)) {

      prepareRemovers(updaters, user, account);

    }
    if (op.getOp().equals(replace)) {

      prepareReplacers(updaters, user, account);
    }

    if (updaters.isEmpty()) {
      throw new ScimPatchOperationNotSupported(op.getOp() + " operation not supported");
    }

    return updaters;
  }

}
