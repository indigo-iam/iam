package it.infn.mw.iam.api.scim.updater.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class PasswordUpdater implements Updater<IamAccount, String> {

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Override
  public boolean add(IamAccount account, String password) {

    if (password == null) {
      return false;
    }
    final String encodedPassword = passwordEncoder.encode(password);
    if (account.getPassword().equals(encodedPassword)) {
      return false;
    }
    account.setPassword(encodedPassword);
    return true;
  }

  @Override
  public boolean remove(IamAccount accpunt, String password) {

    throw new ScimPatchOperationNotSupported("Remove password is not supported");
  }

  @Override
  public boolean replace(IamAccount account, String password) {

    return add(account, password);
  }

}
