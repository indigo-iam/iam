package it.infn.mw.iam.audit;

import static it.infn.mw.iam.audit.IamAuditField.CATEGORY;
import static it.infn.mw.iam.audit.IamAuditField.DETAILS;
import static it.infn.mw.iam.audit.IamAuditField.FAILURE_TYPE;
import static it.infn.mw.iam.audit.IamAuditField.GENERATED_BY;
import static it.infn.mw.iam.audit.IamAuditField.MESSAGE;
import static it.infn.mw.iam.audit.IamAuditField.PRINCIPAL;
import static it.infn.mw.iam.audit.IamAuditField.SOURCE;
import static it.infn.mw.iam.audit.IamAuditField.TARGET;
import static it.infn.mw.iam.audit.IamAuditField.TYPE;
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

    data.clear();
    data.put(SOURCE, event.getSource().getClass().getSimpleName());
    data.put(CATEGORY, AUTHN_CATEGORY);
    data.put(TYPE, event.getClass().getSimpleName());
    data.put(PRINCIPAL, event.getAuthentication().getName());
    if (event.getAuthentication().getDetails() != null) {
      data.put(DETAILS, event.getAuthentication().getDetails());
    }

    if (event instanceof AbstractAuthenticationFailureEvent) {
      AbstractAuthenticationFailureEvent localEvent = (AbstractAuthenticationFailureEvent) event;
      data.put(FAILURE_TYPE, localEvent.getException().getClass().getSimpleName());
      data.put(MESSAGE, localEvent.getException().getMessage());

    } else if (event instanceof AuthenticationSwitchUserEvent) {
      AuthenticationSwitchUserEvent localEvent = (AuthenticationSwitchUserEvent) event;
      data.put(TARGET, localEvent.getTargetUser().getUsername());
    } else if (event instanceof InteractiveAuthenticationSuccessEvent) {
      InteractiveAuthenticationSuccessEvent localEvent =
          (InteractiveAuthenticationSuccessEvent) event;
      data.put(GENERATED_BY, localEvent.getGeneratedBy().getSimpleName());
    }

    logger.info(String.format("AuditEvent: %s", IamAuditUtils.printAuditData(data)));
  }

  public Map<String, Object> getAuditData() {
    return data;
  }

}

