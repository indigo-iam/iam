package it.infn.mw.iam.api.scim.updater.user;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class NameUpdater implements Updater<IamAccount, ScimName> {

  @Override
  public boolean add(IamAccount a, ScimName name) {

    return this.replace(a, name);
  }

  @Override
  public boolean remove(IamAccount a, ScimName name) {

    throw new ScimPatchOperationNotSupported("Remove Name not supported");
  }

  @Override
  public boolean replace(IamAccount a, ScimName name) {

    if (name == null) {
      return false;
    }

    boolean hasChanged = false;

    if (name.getGivenName() != null) {
      if (!name.getGivenName().equals(a.getUserInfo().getGivenName())) {
        a.getUserInfo().setGivenName(name.getGivenName());
        hasChanged = true;
      }
    }
    if (name.getMiddleName() != null) {
      if (!name.getMiddleName().equals(a.getUserInfo().getMiddleName())) {
        a.getUserInfo().setMiddleName(name.getMiddleName());
        hasChanged = true;
      }
    }
    if (name.getFamilyName() != null) {
      if (!name.getFamilyName().equals(a.getUserInfo().getFamilyName())) {
        a.getUserInfo().setFamilyName(name.getFamilyName());
        hasChanged = true;
      }
    }

    return hasChanged;
  }

}
