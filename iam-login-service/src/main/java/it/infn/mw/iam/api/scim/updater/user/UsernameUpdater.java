package it.infn.mw.iam.api.scim.updater.user;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class UsernameUpdater implements Updater<IamAccount, String> {

  @Autowired
  private IamAccountRepository accountRepository;

  private boolean isValid(IamAccount account, String username) {

    Preconditions.checkNotNull(account);

    if (username != null) {
      if (accountRepository.findByUsernameWithDifferentUUID(username, account.getUuid())
        .isPresent()) {
        throw new ScimResourceExistsException(
            "username " + username + " already assigned to another user");
      }
    }

    return true;
  }

  @Override
  public boolean add(IamAccount account, String username) {

    return replace(account, username);
  }

  @Override
  public boolean remove(IamAccount accpunt, String username) {

    throw new ScimPatchOperationNotSupported("Remove username is not supported");
  }

  @Override
  public boolean replace(IamAccount account, String username) {

    if (!isValid(account, username)) {
      return false;
    }
    if (username == null) {
      return false;
    }
    if (account.getUsername().equals(username)) {
      return false;
    }
    account.setUsername(username);
    return true;
  }
}
