package it.infn.mw.iam.api.scim.updater.user;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class ActiveUpdater implements Updater<IamAccount, Boolean> {

  @Override
  public boolean add(IamAccount account, Boolean isActive) {

    return replace(account, isActive);
  }

  @Override
  public boolean remove(IamAccount account, Boolean isActive) {
    throw new ScimPatchOperationNotSupported("Remove active is not supported");
  }

  @Override
  public boolean replace(IamAccount account, Boolean isActive) {

    if (isActive == null) {
      return false;
    }
    if (account.isActive() ^ isActive) {
      account.setActive(isActive);
      return true;
    }
    return false;
  }

}
