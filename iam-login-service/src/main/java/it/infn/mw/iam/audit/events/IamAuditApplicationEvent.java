package it.infn.mw.iam.audit.events;



import java.util.Map;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.collect.Maps;

import it.infn.mw.iam.audit.IamAuditField;

public class IamAuditApplicationEvent extends ApplicationEvent {

  public static enum IamEventCategory {
    NONE,
    ACCOUNT,
    GROUP,
    REGISTRATION,
    AUTHENTICATION,
    AUTHORIZATION
  }

  private static final long serialVersionUID = -6276169409979227109L;
  public static final String NULL_PRINCIPAL = "<unknown>";

  private final String principal;
  private final String message;
  private final IamEventCategory category;

  private final Map<String, Object> data;

  public IamAuditApplicationEvent(IamEventCategory category, Object source, String message,
      Map<String, Object> data) {
    super(source);
    this.message = message;
    this.data = data;
    this.category = category;
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    if (auth == null) {
      this.principal = NULL_PRINCIPAL;
    } else {
      this.principal = auth.getName();
    }
  }

  public IamAuditApplicationEvent(IamEventCategory category, Object source, String message) {
    this(category, source, message, Maps.newLinkedHashMap());
  }

  protected IamAuditApplicationEvent(IamEventCategory category, Object source) {
    this(category, source, null, Maps.newLinkedHashMap());
  }

  public String getPrincipal() {
    return principal;
  }

  public String getMessage() {
    return message;
  }

  public IamEventCategory getCategory() {
    return category;
  }
  
  public Map<String, Object> getData() {
    return data;
  }

  protected void addAuditData() {
    getData().put(IamAuditField.SOURCE, super.source.getClass().getSimpleName());
    getData().put(IamAuditField.PRINCIPAL, principal);
    getData().put(IamAuditField.MESSAGE, message);
  }

  public void build() {
    addAuditData();
  }

}
