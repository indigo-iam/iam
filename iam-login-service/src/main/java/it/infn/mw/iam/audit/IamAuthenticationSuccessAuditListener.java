package it.infn.mw.iam.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.auth.IamAuthenticationSuccessEvent;

@Component
public class IamAuthenticationSuccessAuditListener
    implements ApplicationListener<AbstractAuthenticationEvent> {

  private final AuditEventLogger logger;

  @Autowired
  public IamAuthenticationSuccessAuditListener(AuditEventLogger logger) {
    this.logger = logger;
  }

  @Override
  public void onApplicationEvent(AbstractAuthenticationEvent event) {

    if ((event instanceof AuthenticationSuccessEvent)
        || (event instanceof InteractiveAuthenticationSuccessEvent)) {
      IamAuthenticationSuccessEvent ev = new IamAuthenticationSuccessEvent(event);
      logger.logAuditEvent(ev);
    }

  }

}

