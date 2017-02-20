package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class RegistrationEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -3428745338283606683L;

  private static final String category = "Registration";

  private final IamRegistrationRequest request;

  public RegistrationEvent(Object source, IamRegistrationRequest request, String message) {
    super(source, message);
    this.request = request;
  }

  public IamRegistrationRequest getRequest() {
    return request;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put("category", category);
    getData().put("type", this.getClass().getSimpleName());
    getData().put("requestUuid", request.getUuid());
    getData().put("requestStatus", request.getStatus());
    getData().put("user", request.getAccount().getUsername());
  }
}
