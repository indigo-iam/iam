package it.infn.mw.iam.audit.events.auth;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.utils.IamAuthenticationSuccessSerializer;

public class IamAuthenticationSuccessEvent extends IamAuthenticationEvent {

  private static final long serialVersionUID = 1L;

  @JsonSerialize(using = IamAuthenticationSuccessSerializer.class)
  final AbstractAuthenticationEvent sourceEvent;

  public IamAuthenticationSuccessEvent(AbstractAuthenticationEvent authEvent) {
    super(authEvent,
        String.format("%s authenticated succesfully", authEvent.getAuthentication().getName()));
    this.sourceEvent = authEvent;
  }

  public AbstractAuthenticationEvent getSourceEvent() {
    return sourceEvent;
  }

}
