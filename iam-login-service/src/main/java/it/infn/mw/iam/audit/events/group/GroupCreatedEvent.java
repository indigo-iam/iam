package it.infn.mw.iam.audit.events.group;

import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupCreatedEvent extends GroupEvent {

  private static final long serialVersionUID = 8991030562775896932L;

  public GroupCreatedEvent(Object source, IamGroup group, String message) {
    super(source, group, message);
  }

}
