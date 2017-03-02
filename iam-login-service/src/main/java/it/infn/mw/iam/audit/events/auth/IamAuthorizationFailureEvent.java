package it.infn.mw.iam.audit.events.auth;

import org.springframework.security.access.event.AuthorizationFailureEvent;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.utils.IamAuthorizationFailureEventSerializer;

public class IamAuthorizationFailureEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 1L;
  
  @JsonSerialize(using=IamAuthorizationFailureEventSerializer.class)
  final AuthorizationFailureEvent sourceAuthzEvent;

  public IamAuthorizationFailureEvent(AuthorizationFailureEvent event) {
    super(IamEventCategory.AUTHORIZATION,event.getSource(), 
        event.getAccessDeniedException().getMessage());
    this.sourceAuthzEvent = event;
  }

  public AuthorizationFailureEvent getSourceAuthzEvent() {
    return sourceAuthzEvent;
  }
}
