package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupRemoveEvent extends GroupEvent {

  private static final long serialVersionUID = 4469452544575412615L;

  public GroupRemoveEvent(Object source, IamGroup group, String message) {
    super(source, group, message);
  }

}
