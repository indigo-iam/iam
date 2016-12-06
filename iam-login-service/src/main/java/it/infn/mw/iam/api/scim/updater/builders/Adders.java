package it.infn.mw.iam.api.scim.updater.builders;


import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_GROUP_MEMBERSHIP;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_X509_CERTIFICATE;

import java.util.Collection;
import java.util.Objects;
import java.util.function.Predicate;

import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.DefaultAccountUpdater;
import it.infn.mw.iam.api.scim.updater.util.AccountFinder;
import it.infn.mw.iam.api.scim.updater.util.IdNotBoundChecker;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class Adders extends Replacers {


  final Predicate<Collection<IamOidcId>> oidcIdAddChecks;
  final Predicate<Collection<IamSamlId>> samlIdAddChecks;
  final Predicate<Collection<IamSshKey>> sshKeyAddChecks;
  final Predicate<Collection<IamX509Certificate>> x509CertificateAddChecks;
  final Predicate<Collection<IamGroup>> addMembersChecks;

  final AccountFinder<IamOidcId> findByOidcId;
  final AccountFinder<IamSamlId> findBySamlId;
  final AccountFinder<IamSshKey> findBySshKey;
  final AccountFinder<IamX509Certificate> findByX509Certificate;

  private Predicate<Collection<IamOidcId>> buildOidcIdsAddChecks() {

    Predicate<IamOidcId> oidcIdNotBound =
        new IdNotBoundChecker<IamOidcId>(findByOidcId, account, (id, a) -> {
          throw new ScimResourceExistsException(
              "OpenID connect account " + id + " already bound to another user");
        });

    Predicate<Collection<IamOidcId>> oidcIdsNotBound = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(id -> oidcIdNotBound.test(id));
      return true;
    };

    Predicate<Collection<IamOidcId>> oidcIdsNotOwned = c -> {
      return !account.getOidcIds().containsAll(c);
    };

    return oidcIdsNotBound.and(oidcIdsNotOwned);

  }

  private Predicate<Collection<IamSamlId>> buildSamlIdsAddChecks() {
    Predicate<IamSamlId> samlIdNotBound =
        new IdNotBoundChecker<IamSamlId>(findBySamlId, account, (id, a) -> {
          throw new ScimResourceExistsException(
              "SAML account " + id + " already bound to another user");
        });

    Predicate<Collection<IamSamlId>> samlIdsNotBound = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(id -> samlIdNotBound.test(id));
      return true;
    };

    Predicate<Collection<IamSamlId>> samlIdsNotOwned = c -> {
      return !account.getSamlIds().containsAll(c);
    };

    return samlIdsNotBound.and(samlIdsNotOwned);

  }

  private Predicate<Collection<IamSshKey>> buildSshKeyAddChecks() {
    Predicate<IamSshKey> sshKeyNotBound =
        new IdNotBoundChecker<IamSshKey>(findBySshKey, account, (key, a) -> {
          throw new ScimResourceExistsException(
              "SSH key '" + key.getValue() + "' already bound to another user");
        });

    Predicate<Collection<IamSshKey>> sshKeysNotBound = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(id -> sshKeyNotBound.test(id));
      return true;
    };

    Predicate<Collection<IamSshKey>> sshKeysNotOwned = c -> {
      return !account.getSshKeys().containsAll(c);
    };


    return sshKeysNotBound.and(sshKeysNotOwned);
  }

  private Predicate<Collection<IamX509Certificate>> buildX509CertificateAddChecks() {
    Predicate<IamX509Certificate> x509CertificateNotBound =
        new IdNotBoundChecker<IamX509Certificate>(findByX509Certificate, account, (cert, a) -> {
          throw new ScimResourceExistsException(
              "X509 Certificate " + cert.getCertificate() + "' already bound to another user");
        });

    Predicate<Collection<IamX509Certificate>> x509CertificatesNotBound = c -> {
      c.removeIf(Objects::isNull);
      c.stream().forEach(id -> x509CertificateNotBound.test(id));
      return true;
    };

    Predicate<Collection<IamX509Certificate>> x509CertificatesNotOwned = c -> {
      return !account.getX509Certificates().containsAll(c);
    };


    return x509CertificatesNotBound.and(x509CertificatesNotOwned);
  }

  private Predicate<Collection<IamGroup>> buildAddMembersCheck() {

    Predicate<Collection<IamGroup>> notAlreadyMember = a -> {
      return !account.getGroups().containsAll(a);
    };

    return notAlreadyMember;
  }

  public Adders(IamAccountRepository repo, PasswordEncoder encoder, IamAccount account) {
    super(repo, encoder, account);

    findByOidcId = id -> repo.findByOidcId(id.getIssuer(), id.getSubject());
    findBySamlId = id -> repo.findBySamlId(id.getIdpId(), id.getUserId());
    findBySshKey = key -> repo.findBySshKeyValue(key.getValue());
    findByX509Certificate = cert -> repo.findByCertificate(cert.getCertificate());

    oidcIdAddChecks = buildOidcIdsAddChecks();
    samlIdAddChecks = buildSamlIdsAddChecks();
    sshKeyAddChecks = buildSshKeyAddChecks();
    x509CertificateAddChecks = buildX509CertificateAddChecks();
    addMembersChecks = buildAddMembersCheck();
  }

  public AccountUpdater oidcId(Collection<IamOidcId> newOidcIds) {

    return new DefaultAccountUpdater<Collection<IamOidcId>>(account, ACCOUNT_ADD_OIDC_ID,
        account::linkOidcIds, newOidcIds, oidcIdAddChecks);
  }

  public AccountUpdater samlId(Collection<IamSamlId> newSamlIds) {

    return new DefaultAccountUpdater<Collection<IamSamlId>>(account, ACCOUNT_ADD_SAML_ID,
        account::linkSamlIds, newSamlIds, samlIdAddChecks);
  }

  public AccountUpdater sshKey(Collection<IamSshKey> newSshKeys) {

    return new DefaultAccountUpdater<Collection<IamSshKey>>(account, ACCOUNT_ADD_SSH_KEY,
        account::linkSshKeys, newSshKeys, sshKeyAddChecks);
  }

  public AccountUpdater x509Certificate(Collection<IamX509Certificate> newX509Certificates) {

    return new DefaultAccountUpdater<Collection<IamX509Certificate>>(account, ACCOUNT_ADD_X509_CERTIFICATE,
        account::linkX509Certificates, newX509Certificates, x509CertificateAddChecks);
  }

  public AccountUpdater group(Collection<IamGroup> groups) {

    return new DefaultAccountUpdater<Collection<IamGroup>>(account, ACCOUNT_ADD_GROUP_MEMBERSHIP,
        account::linkMembers, groups, addMembersChecks);
  }
}
