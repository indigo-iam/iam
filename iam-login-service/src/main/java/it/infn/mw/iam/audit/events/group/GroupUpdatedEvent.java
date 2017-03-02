package it.infn.mw.iam.audit.events.group;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.audit.utils.UpdaterTypeSerializer;
import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupUpdatedEvent extends GroupEvent {

  private static final long serialVersionUID = -3060371331110710895L;

  @JsonSerialize(using=UpdaterTypeSerializer.class)
  private final UpdaterType updaterType;

  public GroupUpdatedEvent(Object source, IamGroup group, UpdaterType updateType, String message) {
    super(source, group, message);
    this.updaterType = updateType;
  }


  public UpdaterType getUpdaterType() {
    return updaterType;
  }

}
