package it.infn.mw.iam.audit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.stereotype.Component;

@Component
public class IamAuthorizationAuditListener
    implements ApplicationListener<AbstractAuthorizationEvent> {

  private static final Log logger = LogFactory.getLog(IamAuthorizationAuditListener.class);

  @Override
  public void onApplicationEvent(AbstractAuthorizationEvent event) {

    logger.info(event);
  }

}

