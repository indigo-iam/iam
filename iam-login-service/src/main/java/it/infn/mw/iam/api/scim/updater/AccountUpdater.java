package it.infn.mw.iam.api.scim.updater;

import it.infn.mw.iam.persistence.model.IamAccount;

public interface AccountUpdater extends Updater {

  public IamAccount getAccount();
}
