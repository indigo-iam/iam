package it.infn.mw.iam.api.scim.updater.user;

import java.util.List;

import org.mitre.openid.connect.model.Address;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.converter.AddressConverter;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimAddress;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class AddressUpdater implements Updater<IamAccount, List<ScimAddress>> {

  @Autowired
  private AddressConverter addressConverter;

  private boolean isValid(IamAccount account, List<ScimAddress> addresses) {
    
    Preconditions.checkNotNull(account);
    if (addresses == null) {
      return false;
    }
    if (addresses.isEmpty()) {
      return false;
    }
    Preconditions.checkArgument(addresses.size() == 1,
        "Specifying more than one address is not supported!");
    Preconditions.checkNotNull(addresses.get(0), "Null address found");
    return true;
  }

  @Override
  public boolean add(IamAccount account, List<ScimAddress> addresses) {

    return replace(account, addresses);
  }

  @Override
  public boolean remove(IamAccount account, List<ScimAddress> addresses) {

    if (!isValid(account, addresses)) {
      return false;
    }
    
    final Address address = addressConverter.fromScim(addresses.get(0));

    if (address.equals(account.getUserInfo().getAddress())) {
      throw new ScimResourceNotFoundException("Address " + address + " not found");
    }
    account.getUserInfo().setAddress(null);
    return true;
  }

  @Override
  public boolean replace(IamAccount account, List<ScimAddress> addresses) {

    if (!isValid(account, addresses)) {
      return false;
    }

    final Address address = addressConverter.fromScim(addresses.get(0));

    if (address.equals(account.getUserInfo().getAddress())) {
      return false;
    }

    account.getUserInfo().setAddress(address);
    return true;
  }

}
