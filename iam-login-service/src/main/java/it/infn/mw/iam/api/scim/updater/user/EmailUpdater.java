package it.infn.mw.iam.api.scim.updater.user;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class EmailUpdater implements Updater<IamAccount, List<ScimEmail>> {

  @Autowired
  private IamAccountRepository accountRepository;
  
  private boolean isValid(IamAccount account, List<ScimEmail> emails) {

    Preconditions.checkNotNull(account);
    if (emails == null) {
      return false;
    }
    if (emails.isEmpty()) {
      return false;
    }
    Preconditions.checkArgument(emails.size() == 1,
        "Specifying more than one email is not supported!");
    Preconditions.checkNotNull(emails.get(0), "Null email found");
    Preconditions.checkNotNull(emails.get(0).getValue(), "Null email value found");

    if (accountRepository.findByEmailWithDifferentUUID(emails.get(0).getValue(), account.getUuid())
      .isPresent()) {
      throw new ScimResourceExistsException(
          "email " + emails.get(0).getValue() + " already assigned to another user");
    }
    return true;
  }

  @Override
  public boolean add(IamAccount account, List<ScimEmail> emails) {

    return replace(account, emails);
  }

  @Override
  public boolean remove(IamAccount account, List<ScimEmail> emails) {

    throw new ScimPatchOperationNotSupported("Remove email is not supported");
  }

  @Override
  public boolean replace(IamAccount account, List<ScimEmail> emails) {

    if (!isValid(account, emails)) {
      return false;
    }

    final String email = emails.get(0).getValue();

    if (email.equals(account.getUserInfo().getEmail())) {
      return false;
    }
    account.getUserInfo().setEmail(email);
    return true;
  }

}
