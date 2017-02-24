package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.CATEGORY;
import static it.infn.mw.iam.audit.IamAuditField.GROUP_NAME;
import static it.infn.mw.iam.audit.IamAuditField.GROUP_UUID;
import static it.infn.mw.iam.audit.IamAuditField.TYPE;

import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -6490018220086638357L;

  private static final String categoryValue = "GROUP";

  private final IamGroup group;

  public GroupEvent(Object source, IamGroup group, String message) {
    super(source, message);
    this.group = group;
  }

  public IamGroup getgroup() {
    return group;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(CATEGORY, categoryValue);
    getData().put(TYPE, this.getClass().getSimpleName());
    getData().put(GROUP_UUID, group.getUuid());
    getData().put(GROUP_NAME, group.getName());
  }
}
