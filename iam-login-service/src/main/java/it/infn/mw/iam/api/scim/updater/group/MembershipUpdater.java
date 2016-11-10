package it.infn.mw.iam.api.scim.updater.group;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class MembershipUpdater implements Updater<IamAccount, IamGroup> {

  @Autowired
  private IamAccountRepository accountRepository;

  @Override
  public boolean add(IamAccount account, IamGroup group) {

    if (account.isMemberOf(group)) {
      return false;
    }
    account.getGroups().add(group);
    account.touch();
    accountRepository.save(account);
    return true;
  }

  @Override
  public boolean remove(IamAccount account, IamGroup group) {

    if (!account.isMemberOf(group)) {
      return false;
    }
    account.getGroups().remove(group);
    account.touch();
    accountRepository.save(account);
    return true;
  }

  @Override
  public boolean replace(IamAccount account, IamGroup group) {

    return add(account, group);
  }
}
