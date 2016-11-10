package it.infn.mw.iam.api.scim.updater;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.updater.user.AddressUpdater;
import it.infn.mw.iam.api.scim.updater.user.EmailUpdater;
import it.infn.mw.iam.api.scim.updater.user.NameUpdater;
import it.infn.mw.iam.api.scim.updater.user.PasswordUpdater;
import it.infn.mw.iam.api.scim.updater.user.PhotoUpdater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class MeUpdater implements Updater<IamAccount, ScimUser> {

  @Autowired
  private IamAccountRepository accountRepository;
  @Autowired
  private NameUpdater nameUpdater;
  @Autowired
  private PhotoUpdater photoUpdater;
  @Autowired
  private PasswordUpdater passwordUpdater;
  @Autowired
  private EmailUpdater emailUpdater;
  @Autowired
  private AddressUpdater addressUpdater;

  @Override
  public boolean add(IamAccount a, ScimUser u) {

    boolean hasChanged = false;

    hasChanged |= nameUpdater.add(a, u.getName());
    hasChanged |= emailUpdater.add(a, u.getEmails());
    hasChanged |= addressUpdater.add(a, u.getAddresses());
    hasChanged |= passwordUpdater.add(a, u.getPassword());
    hasChanged |= photoUpdater.add(a, u.getPhotos());

    if (hasChanged) {
      a.touch();
      accountRepository.save(a);
    }
    return hasChanged;
  }

  @Override
  public boolean remove(IamAccount a, ScimUser u) {

    boolean hasChanged = false;

    hasChanged |= addressUpdater.remove(a, u.getAddresses());
    hasChanged |= photoUpdater.remove(a, u.getPhotos());

    if (hasChanged) {
      a.touch();
      accountRepository.save(a);
    }
    return hasChanged;
  }

  @Override
  public boolean replace(IamAccount a, ScimUser u) {

    boolean hasChanged = false;

    hasChanged |= nameUpdater.replace(a, u.getName());
    hasChanged |= emailUpdater.replace(a, u.getEmails());
    hasChanged |= addressUpdater.replace(a, u.getAddresses());
    hasChanged |= passwordUpdater.replace(a, u.getPassword());
    hasChanged |= photoUpdater.replace(a, u.getPhotos());

    if (hasChanged) {
      a.touch();
      accountRepository.save(a);
    }
    return hasChanged;
  }
}
