package it.infn.mw.iam.audit.events.auth;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

public abstract class IamAuthenticationEvent extends IamAuditApplicationEvent {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public IamAuthenticationEvent(AbstractAuthenticationEvent authEvent, String message) {
    super(IamEventCategory.AUTHENTICATION, authEvent.getSource(), message);
  }

}
