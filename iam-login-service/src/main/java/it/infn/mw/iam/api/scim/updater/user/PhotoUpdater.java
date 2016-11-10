package it.infn.mw.iam.api.scim.updater.user;

import java.util.List;

import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class PhotoUpdater implements Updater<IamAccount, List<ScimPhoto>> {

  private boolean isValid(IamAccount account, List<ScimPhoto> photos) {

    Preconditions.checkNotNull(account);
    if (photos == null) {
      return false;
    }
    if (photos.isEmpty()) {
      return false;
    }
    Preconditions.checkArgument(photos.size() == 1,
        "Specifying more than one photo is not supported!");
    Preconditions.checkNotNull(photos.get(0), "Null photo found");
    Preconditions.checkNotNull(photos.get(0).getValue(), "Null photo value found");
    return true;
  }

  @Override
  public boolean add(IamAccount account, List<ScimPhoto> photos) {

    if (!isValid(account, photos)) {
      return false;
    }

    final String picture = photos.get(0).getValue();

    if (picture.equals(account.getUserInfo().getPicture())) {
      return false;
    }

    account.getUserInfo().setPicture(photos.get(0).getValue());
    return true;
  }

  @Override
  public boolean remove(IamAccount account, List<ScimPhoto> photos) {

    if (!isValid(account, photos)) {
      return false;
    }

    final String picture = photos.get(0).getValue();
    if (!picture.equals(account.getUserInfo().getPicture())) {
      throw new ScimResourceNotFoundException("Photo value " + picture + " not found");
    }
    account.getUserInfo().setPicture(null);
    return true;
  }

  @Override
  public boolean replace(IamAccount account, List<ScimPhoto> photos) {

    if (!isValid(account, photos)) {
      return false;
    }

    final String picture = photos.get(0).getValue();

    if (picture.equals(account.getUserInfo().getPicture())) {
      return false;
    }
    account.getUserInfo().setPicture(picture);
    return true;
  }

}
