package it.infn.mw.iam.audit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.stereotype.Component;

@Component
public class IamAuthenticationAuditListener
    implements ApplicationListener<AbstractAuthenticationEvent> {

  private static final Log logger = LogFactory.getLog(IamAuthenticationAuditListener.class);

  @Override
  public void onApplicationEvent(AbstractAuthenticationEvent event) {

    logger.info(event);
  }

}

