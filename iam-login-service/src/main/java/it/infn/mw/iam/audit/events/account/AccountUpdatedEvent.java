package it.infn.mw.iam.audit.events.account;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.audit.utils.UpdaterTypeSerializer;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountUpdatedEvent extends AccountEvent {

  private static final long serialVersionUID = 5449634442314906657L;

  @JsonSerialize(using=UpdaterTypeSerializer.class)
  private final UpdaterType updaterType;

  public AccountUpdatedEvent(Object source, IamAccount account, UpdaterType type, String message) {
    super(source, account, message);
    this.updaterType = type;
  }
  
  public UpdaterType getUpdaterType() {
    return updaterType;
  }
}
