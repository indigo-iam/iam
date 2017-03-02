package it.infn.mw.iam.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.auth.IamAuthenticationFailureEvent;

@Component
public class IamAuthenticationFailureAuditListener 
  implements ApplicationListener<AbstractAuthenticationFailureEvent>{

  private final AuditEventLogger logger;
  
  @Autowired
  public IamAuthenticationFailureAuditListener(AuditEventLogger logger) {
    this.logger = logger;
  }
  
  @Override
  public void onApplicationEvent(AbstractAuthenticationFailureEvent event) {
    IamAuthenticationFailureEvent ev = new IamAuthenticationFailureEvent(event);
    logger.logAuditEvent(ev);
  }

}
