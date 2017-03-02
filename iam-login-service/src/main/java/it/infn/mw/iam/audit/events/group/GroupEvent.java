package it.infn.mw.iam.audit.events.group;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.utils.IamGroupSerializer;
import it.infn.mw.iam.persistence.model.IamGroup;


public abstract class GroupEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -6490018220086638357L;
  
  @JsonSerialize(using=IamGroupSerializer.class)
  private final IamGroup group;

  public GroupEvent(Object source, IamGroup group, String message) {
    super(IamEventCategory.GROUP,source, message);
    this.group = group;
  }

  public IamGroup getGroup() {
    return group;
  }
  
}
