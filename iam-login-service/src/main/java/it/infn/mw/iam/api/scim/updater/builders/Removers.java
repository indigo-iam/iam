package it.infn.mw.iam.api.scim.updater.builders;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_GROUP_MEMBERSHIP;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_X509_CERTIFICATE;

import java.util.Collection;
import java.util.Collections;

import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.DefaultAccountUpdater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class Removers extends AccountBuilderSupport {

  public Removers(IamAccountRepository repo, IamAccount account) {
    super(repo, account);
  }

  public AccountUpdater oidcId(Collection<IamOidcId> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamOidcId>>(account, ACCOUNT_REMOVE_OIDC_ID, account::unlinkOidcIds,
        toBeRemoved, i -> !Collections.disjoint(account.getOidcIds(), i));
  }

  public AccountUpdater samlId(Collection<IamSamlId> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamSamlId>>(account, ACCOUNT_REMOVE_SAML_ID, account::unlinkSamlIds,
        toBeRemoved, i -> !Collections.disjoint(account.getSamlIds(), i));
  }

  public AccountUpdater sshKey(Collection<IamSshKey> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamSshKey>>(account, ACCOUNT_REMOVE_SSH_KEY, account::unlinkSshKeys,
        toBeRemoved, i -> !Collections.disjoint(account.getSshKeys(), i));
  }

  public AccountUpdater x509Certificate(Collection<IamX509Certificate> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamX509Certificate>>(account, ACCOUNT_REMOVE_X509_CERTIFICATE,
        account::unlinkX509Certificates, toBeRemoved,
        i -> !Collections.disjoint(account.getX509Certificates(), i));
  }

  public AccountUpdater group(Collection<IamGroup> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamGroup>>(account, ACCOUNT_REMOVE_GROUP_MEMBERSHIP, account::unlinkMembers,
        toBeRemoved, i -> !Collections.disjoint(account.getGroups(), i));
  }

  public AccountUpdater picture(String picture) {
    final IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String>(account, ACCOUNT_REMOVE_PICTURE, ui::getPicture, ui::setPicture, null);
  }
}
