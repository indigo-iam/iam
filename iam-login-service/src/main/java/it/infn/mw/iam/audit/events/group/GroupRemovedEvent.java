package it.infn.mw.iam.audit.events.group;

import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupRemovedEvent extends GroupEvent {

  private static final long serialVersionUID = 4469452544575412615L;

  public GroupRemovedEvent(Object source, IamGroup group, String message) {
    super(source, group, message);
  }

}
