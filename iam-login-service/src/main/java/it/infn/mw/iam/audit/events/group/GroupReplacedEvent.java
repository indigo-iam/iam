package it.infn.mw.iam.audit.events.group;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.utils.IamGroupSerializer;
import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupReplacedEvent extends GroupEvent {

  private static final long serialVersionUID = -2464733224199680363L;

  @JsonSerialize(using=IamGroupSerializer.class)
  private final IamGroup previousGroup;

  public GroupReplacedEvent(Object source, IamGroup group, IamGroup previousGroup, String message) {
    super(source, group, message);
    this.previousGroup = previousGroup;
  }

  public IamGroup getPreviousGroup() {
    return previousGroup;
  }
}
