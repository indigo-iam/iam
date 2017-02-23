package it.infn.mw.iam.audit;

import static it.infn.mw.iam.audit.IamAuditField.category;
import static it.infn.mw.iam.audit.IamAuditField.details;
import static it.infn.mw.iam.audit.IamAuditField.failureType;
import static it.infn.mw.iam.audit.IamAuditField.generatedBy;
import static it.infn.mw.iam.audit.IamAuditField.message;
import static it.infn.mw.iam.audit.IamAuditField.principal;
import static it.infn.mw.iam.audit.IamAuditField.source;
import static it.infn.mw.iam.audit.IamAuditField.target;
import static it.infn.mw.iam.audit.IamAuditField.type;
import static it.infn.mw.iam.audit.IamAuditUtils.AUTHN_CATEGORY;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent;
import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;

@Component
public class IamAuthenticationAuditListener
    implements ApplicationListener<AbstractAuthenticationEvent> {

  private static final Log logger = LogFactory.getLog(IamAuthenticationAuditListener.class);

  private Map<String, Object> data = Maps.newLinkedHashMap();

  @Override
  public void onApplicationEvent(AbstractAuthenticationEvent event) {

    data = Maps.newLinkedHashMap();
    data.put(source, event.getSource().getClass().getSimpleName());
    data.put(category, AUTHN_CATEGORY);
    data.put(type, event.getClass().getSimpleName());
    data.put(principal, event.getAuthentication().getName());
    if (event.getAuthentication().getDetails() != null) {
      data.put(details, event.getAuthentication().getDetails());
    }

    if (event instanceof AbstractAuthenticationFailureEvent) {
      AbstractAuthenticationFailureEvent localEvent = (AbstractAuthenticationFailureEvent) event;
      data.put(failureType, localEvent.getException().getClass().getSimpleName());
      data.put(message, localEvent.getException().getMessage());

    } else if (event instanceof AuthenticationSwitchUserEvent) {
      AuthenticationSwitchUserEvent localEvent = (AuthenticationSwitchUserEvent) event;
      data.put(target, localEvent.getTargetUser().getUsername());
    } else if (event instanceof InteractiveAuthenticationSuccessEvent) {
      InteractiveAuthenticationSuccessEvent localEvent =
          (InteractiveAuthenticationSuccessEvent) event;
      data.put(generatedBy, localEvent.getGeneratedBy().getSimpleName());
    }

    logger.info(String.format("AuditEvent: %s", IamAuditUtils.printAuditData(data)));
  }

  public Map<String, Object> getAuditData() {
    return data;
  }

}

