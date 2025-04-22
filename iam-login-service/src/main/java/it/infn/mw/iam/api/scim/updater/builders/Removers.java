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

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_GROUP_MEMBERSHIP;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_X509_CERTIFICATE;
import static java.util.Objects.isNull;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.DefaultAccountUpdater;
import it.infn.mw.iam.audit.events.account.PictureRemovedEvent;
import it.infn.mw.iam.audit.events.account.group.GroupMembershipRemovedEvent;
import it.infn.mw.iam.audit.events.account.oidc.OidcAccountRemovedEvent;
import it.infn.mw.iam.audit.events.account.saml.SamlAccountRemovedEvent;
import it.infn.mw.iam.audit.events.account.ssh.SshKeyRemovedEvent;
import it.infn.mw.iam.audit.events.account.x509.X509CertificateRemovedEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class Removers extends AccountBuilderSupport {

  final Consumer<Collection<IamSshKey>> unlinkSshKeys;

  final Consumer<Collection<IamGroup>> unlinkGroups;

  public Removers(IamAccountRepository repo, IamAccountService accountService, IamAccount account) {
    super(repo, accountService, account);
    unlinkSshKeys = keys -> {
      for (IamSshKey k : keys) {
        if (!isNull(k)) {
          accountService.removeSshKey(account, k);
        }
      }
    };
    unlinkGroups = groups -> {
      for (IamGroup g : groups) {
        if (!isNull(g)) {
          accountService.removeFromGroup(account, g);
        }
      }
    };
  }

  public AccountUpdater group(Collection<IamGroup> tobeRemoved) {

    return new DefaultAccountUpdater<Collection<IamGroup>, GroupMembershipRemovedEvent>(account,
        ACCOUNT_REMOVE_GROUP_MEMBERSHIP, unlinkGroups, tobeRemoved, i -> {
          Set<String> accountGroupNames = account.getGroups()
            .stream()
            .map(m -> m.getGroup().getName())
            .collect(Collectors.toSet());

          Set<String> toRemoveNames = i.stream().map(IamGroup::getName).collect(Collectors.toSet());

          return !Collections.disjoint(accountGroupNames, toRemoveNames);
        }, null);
  }

  public AccountUpdater oidcId(Collection<IamOidcId> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamOidcId>, OidcAccountRemovedEvent>(account,
        ACCOUNT_REMOVE_OIDC_ID, account::unlinkOidcIds, toBeRemoved,
        i -> !Collections.disjoint(account.getOidcIds(), i), OidcAccountRemovedEvent::new);
  }

  public AccountUpdater samlId(Collection<IamSamlId> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamSamlId>, SamlAccountRemovedEvent>(account,
        ACCOUNT_REMOVE_SAML_ID, account::unlinkSamlIds, toBeRemoved,
        i -> !Collections.disjoint(account.getSamlIds(), i), SamlAccountRemovedEvent::new);
  }

  public AccountUpdater sshKey(Collection<IamSshKey> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamSshKey>, SshKeyRemovedEvent>(account,
        ACCOUNT_REMOVE_SSH_KEY, unlinkSshKeys, toBeRemoved,
        i -> !Collections.disjoint(account.getSshKeys(), i), SshKeyRemovedEvent::new);
  }

  public AccountUpdater x509Certificate(Collection<IamX509Certificate> toBeRemoved) {

    return new DefaultAccountUpdater<Collection<IamX509Certificate>, X509CertificateRemovedEvent>(
        account, ACCOUNT_REMOVE_X509_CERTIFICATE, account::unlinkX509Certificates, toBeRemoved,
        i -> !Collections.disjoint(account.getX509Certificates(), i),
        X509CertificateRemovedEvent::new);
  }

  public AccountUpdater picture(String picture) {
    final IamUserInfo ui = account.getUserInfo();
    return new DefaultAccountUpdater<String, PictureRemovedEvent>(account, ACCOUNT_REMOVE_PICTURE,
        ui::getPicture, ui::setPicture, null, PictureRemovedEvent::new);
  }
}
