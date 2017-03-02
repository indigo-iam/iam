package it.infn.mw.iam.audit.events.auth;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.utils.IamAuthenticationFailureEventSerializer;

public class IamAuthenticationFailureEvent extends IamAuthenticationEvent {

  private static final long serialVersionUID = 1L;
  
  @JsonSerialize(using=IamAuthenticationFailureEventSerializer.class)
  AbstractAuthenticationFailureEvent sourceEvent;
  
  public IamAuthenticationFailureEvent(AbstractAuthenticationFailureEvent authEvent) {
    super(authEvent, authEvent.getException().getMessage());
  }

  public AbstractAuthenticationFailureEvent getSourceEvent() {
    return sourceEvent;
  }
}
