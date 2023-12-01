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


import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_X509_CERTIFICATE;
import static java.util.Objects.isNull;

import java.util.Collection;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.DefaultAccountUpdater;
import it.infn.mw.iam.api.scim.updater.util.AccountFinder;
import it.infn.mw.iam.api.scim.updater.util.IdNotBoundChecker;
import it.infn.mw.iam.audit.events.account.oidc.OidcAccountAddedEvent;
import it.infn.mw.iam.audit.events.account.saml.SamlAccountAddedEvent;
import it.infn.mw.iam.audit.events.account.ssh.SshKeyAddedEvent;
import it.infn.mw.iam.audit.events.account.x509.X509CertificateAddedEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;

public class Adders extends Replacers {


  final Predicate<Collection<IamOidcId>> oidcIdAddChecks;
  final Predicate<Collection<IamSamlId>> samlIdAddChecks;
  final Predicate<Collection<IamSshKey>> sshKeyAddChecks;
  final Predicate<Collection<IamX509Certificate>> x509CertificateAddChecks;

  final AccountFinder<IamOidcId> findByOidcId;
  final AccountFinder<IamSamlId> findBySamlId;
  final AccountFinder<IamSshKey> findBySshKey;
  final AccountFinder<IamX509Certificate> findByX509CertificateSubject;

  final Consumer<Collection<IamSshKey>> linkSshKeys;

  public Adders(IamAccountRepository repo, IamAccountService accountService,
      PasswordEncoder encoder, IamAccount account, OAuth2TokenEntityService tokenService,
      UsernameValidator usernameValidator) {
    super(repo, accountService, encoder, account, tokenService, usernameValidator);

    findByOidcId = id -> repo.findByOidcId(id.getIssuer(), id.getSubject());
    findBySamlId = repo::findBySamlId;
    findBySshKey = key -> repo.findBySshKeyValue(key.getValue());
    findByX509CertificateSubject = cert -> repo.findByCertificateSubject(cert.getSubjectDn());

    oidcIdAddChecks = buildOidcIdsAddChecks();
    samlIdAddChecks = buildSamlIdsAddChecks();
    sshKeyAddChecks = buildSshKeyAddChecks();
    x509CertificateAddChecks = buildX509CertificateAddChecks();

    linkSshKeys = keys -> {
      for (IamSshKey k : keys) {
        if (!isNull(k)) {
          accountService.addSshKey(account, k);
        }
      }
    };
  }

  private Predicate<Collection<IamOidcId>> buildOidcIdsAddChecks() {

    Predicate<IamOidcId> oidcIdNotBound =
        new IdNotBoundChecker<>(findByOidcId, account, (id, a) -> {
          throw new ScimResourceExistsException(
              "OpenID connect account " + id + " already bound to another user");
        });

    Predicate<Collection<IamOidcId>> oidcIdsNotBound = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(oidcIdNotBound::test);
      return true;
    };

    Predicate<Collection<IamOidcId>> oidcIdsNotOwned = c -> !account.getOidcIds().containsAll(c);

    return oidcIdsNotBound.and(oidcIdsNotOwned);

  }

  private Predicate<Collection<IamSamlId>> buildSamlIdsAddChecks() {

    Predicate<Collection<IamSamlId>> samlIdWellFormed = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(id -> {
        if (Strings.isNullOrEmpty(id.getIdpId())) {
          throw new IllegalArgumentException("idpId cannot be null or empty!");
        }

        if (Strings.isNullOrEmpty(id.getAttributeId())) {
          throw new IllegalArgumentException("attributeId cannot be null or empty!");
        }

        if (Strings.isNullOrEmpty(id.getUserId())) {
          throw new IllegalArgumentException("userId cannot be null or empty!");
        }
      });

      return true;
    };

    Predicate<IamSamlId> samlIdNotBound =
        new IdNotBoundChecker<>(findBySamlId, account, (id, a) -> {
          throw new ScimResourceExistsException(
              "SAML account " + id + " already bound to another user");
        });

    Predicate<Collection<IamSamlId>> samlIdsNotBound = c -> {
      c.stream().forEach(samlIdNotBound::test);
      return true;
    };

    Predicate<Collection<IamSamlId>> samlIdsNotOwned = c -> !account.getSamlIds().containsAll(c);

    return samlIdWellFormed.and(samlIdsNotBound.and(samlIdsNotOwned));

  }

  private Predicate<Collection<IamSshKey>> buildSshKeyAddChecks() {
    Predicate<IamSshKey> sshKeyNotBound =
        new IdNotBoundChecker<>(findBySshKey, account, (key, a) -> {
          throw new ScimResourceExistsException(
              "SSH key '" + key.getValue() + "' already bound to another user");
        });

    Predicate<Collection<IamSshKey>> sshKeysNotBound = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(sshKeyNotBound::test);
      return true;
    };

    Predicate<Collection<IamSshKey>> sshKeysNotOwned = c -> !account.getSshKeys().containsAll(c);

    return sshKeysNotBound.and(sshKeysNotOwned);
  }

  private Predicate<Collection<IamX509Certificate>> buildX509CertificateAddChecks() {
    Predicate<IamX509Certificate> x509CertificateNotBound =
        new IdNotBoundChecker<>(findByX509CertificateSubject, account, (cert, a) -> {
          throw new ScimResourceExistsException("X509 certificate with subject '"
              + cert.getSubjectDn() + "' is already bound to another user");
        });

    Predicate<Collection<IamX509Certificate>> x509CertificatesNotBound = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(x509CertificateNotBound::test);
      return true;
    };

    Predicate<Collection<IamX509Certificate>> x509CertificatesNotOwned =
        c -> !account.getX509Certificates().containsAll(c);

    return x509CertificatesNotBound.and(x509CertificatesNotOwned);
  }

  public AccountUpdater oidcId(Collection<IamOidcId> newOidcIds) {

    return new DefaultAccountUpdater<Collection<IamOidcId>, OidcAccountAddedEvent>(account,
        ACCOUNT_ADD_OIDC_ID, account::linkOidcIds, newOidcIds, oidcIdAddChecks,
        OidcAccountAddedEvent::new);
  }

  public AccountUpdater samlId(Collection<IamSamlId> newSamlIds) {

    return new DefaultAccountUpdater<Collection<IamSamlId>, SamlAccountAddedEvent>(account,
        ACCOUNT_ADD_SAML_ID, account::linkSamlIds, newSamlIds, samlIdAddChecks,
        SamlAccountAddedEvent::new);
  }

  public AccountUpdater sshKey(Collection<IamSshKey> newSshKeys) {
    
    return new DefaultAccountUpdater<Collection<IamSshKey>, SshKeyAddedEvent>(account,
        ACCOUNT_ADD_SSH_KEY, linkSshKeys, newSshKeys, sshKeyAddChecks,
        SshKeyAddedEvent::new);
  }

  public AccountUpdater x509Certificate(Collection<IamX509Certificate> newX509Certificates) {

    return new DefaultAccountUpdater<Collection<IamX509Certificate>, X509CertificateAddedEvent>(
        account, ACCOUNT_ADD_X509_CERTIFICATE, account::linkX509Certificates, newX509Certificates,
        x509CertificateAddChecks, X509CertificateAddedEvent::new);
  }

}
