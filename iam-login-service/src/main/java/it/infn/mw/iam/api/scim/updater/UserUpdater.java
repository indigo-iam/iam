package it.infn.mw.iam.api.scim.updater;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.updater.user.ActiveUpdater;
import it.infn.mw.iam.api.scim.updater.user.AddressUpdater;
import it.infn.mw.iam.api.scim.updater.user.EmailUpdater;
import it.infn.mw.iam.api.scim.updater.user.IndigoUserUpdater;
import it.infn.mw.iam.api.scim.updater.user.NameUpdater;
import it.infn.mw.iam.api.scim.updater.user.PasswordUpdater;
import it.infn.mw.iam.api.scim.updater.user.PhotoUpdater;
import it.infn.mw.iam.api.scim.updater.user.UsernameUpdater;
import it.infn.mw.iam.api.scim.updater.user.X509CertificateUpdater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class UserUpdater implements Updater<IamAccount, ScimUser> {

  @Autowired
  private IamAccountRepository accountRepository;
  @Autowired
  private NameUpdater nameUpdater;
  @Autowired
  private PhotoUpdater photoUpdater;
  @Autowired
  private PasswordUpdater passwordUpdater;
  @Autowired
  private UsernameUpdater usernameUpdater;
  @Autowired
  private ActiveUpdater activeUpdater;
  @Autowired
  private EmailUpdater emailUpdater;
  @Autowired
  private AddressUpdater addressUpdater;
  @Autowired
  private X509CertificateUpdater x509CertificateUpdater;
  @Autowired
  private IndigoUserUpdater indigoUserUpdater;

  @Override
  public boolean add(IamAccount a, ScimUser u) {

    boolean hasChanged = false;

    hasChanged |= usernameUpdater.add(a, u.getUserName());
    hasChanged |= activeUpdater.add(a, u.getActive());
    hasChanged |= nameUpdater.add(a, u.getName());
    hasChanged |= emailUpdater.add(a, u.getEmails());
    hasChanged |= addressUpdater.add(a, u.getAddresses());
    hasChanged |= passwordUpdater.add(a, u.getPassword());
    hasChanged |= photoUpdater.add(a, u.getPhotos());
    hasChanged |= x509CertificateUpdater.add(a, u.getX509Certificates());
    hasChanged |= indigoUserUpdater.add(a, u.getIndigoUser());

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
    hasChanged |= x509CertificateUpdater.remove(a, u.getX509Certificates());
    hasChanged |= indigoUserUpdater.remove(a, u.getIndigoUser());

    if (hasChanged) {
      a.touch();
      accountRepository.save(a);
    }
    return hasChanged;
  }

  @Override
  public boolean replace(IamAccount a, ScimUser u) {

    boolean hasChanged = false;

    hasChanged |= usernameUpdater.replace(a, u.getUserName());
    hasChanged |= activeUpdater.replace(a, u.getActive());
    hasChanged |= nameUpdater.replace(a, u.getName());
    hasChanged |= emailUpdater.replace(a, u.getEmails());
    hasChanged |= addressUpdater.replace(a, u.getAddresses());
    hasChanged |= passwordUpdater.replace(a, u.getPassword());
    hasChanged |= photoUpdater.replace(a, u.getPhotos());
    hasChanged |= x509CertificateUpdater.replace(a, u.getX509Certificates());
    hasChanged |= indigoUserUpdater.replace(a, u.getIndigoUser());

    if (hasChanged) {
      a.touch();
      accountRepository.save(a);
    }
    return hasChanged;
  }
}
