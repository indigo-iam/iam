package it.infn.mw.iam.api.scim.updater.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class IndigoUserUpdater implements Updater<IamAccount, ScimIndigoUser> {

  @Autowired
  private OpenIDConnectAccountUpdater oidcIdConnectAccountUpdater;
  @Autowired
  private SshKeyUpdater sshKeyUpdater;
  @Autowired
  private SamlAccountUpdater samlAccountUpdater;

  private boolean isValid(IamAccount account, ScimIndigoUser indigoUser) throws ScimException {

    Preconditions.checkNotNull(account);

    if (indigoUser == null) {
      return false;
    }
    if (indigoUser.isEmpty()) {
      return false;
    }
    return true;
  }

  @Override
  public boolean add(IamAccount account, ScimIndigoUser indigoUser) {

    if (!isValid(account, indigoUser)) {
      return false;
    }

    boolean hasChanged = false;

    hasChanged |= oidcIdConnectAccountUpdater.add(account, indigoUser.getOidcIds());
    hasChanged |= sshKeyUpdater.add(account, indigoUser.getSshKeys());
    hasChanged |= samlAccountUpdater.add(account, indigoUser.getSamlIds());

    return hasChanged;
  }

  @Override
  public boolean remove(IamAccount account, ScimIndigoUser indigoUser) {

    if (!isValid(account, indigoUser)) {
      return false;
    }

    boolean hasChanged = false;

    hasChanged |= oidcIdConnectAccountUpdater.remove(account, indigoUser.getOidcIds());
    hasChanged |= sshKeyUpdater.remove(account, indigoUser.getSshKeys());
    hasChanged |= samlAccountUpdater.remove(account, indigoUser.getSamlIds());

    return hasChanged;
  }

  @Override
  public boolean replace(IamAccount account, ScimIndigoUser indigoUser) {

    if (!isValid(account, indigoUser)) {
      return false;
    }

    boolean hasChanged = false;

    hasChanged |= sshKeyUpdater.replace(account, indigoUser.getSshKeys());

    return hasChanged;
  }

}
