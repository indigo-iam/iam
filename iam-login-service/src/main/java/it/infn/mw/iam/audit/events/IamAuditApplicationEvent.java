package it.infn.mw.iam.audit.events;



import java.util.Map;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.collect.Maps;

import it.infn.mw.iam.audit.IamAuditField;

public class IamAuditApplicationEvent extends ApplicationEvent {

  private static final long serialVersionUID = -6276169409979227109L;
  public static final String NULL_PRINCIPAL = "<unknown>";

  private final String principal;
  private final String message;
  private final Map<String, Object> data;

  public IamAuditApplicationEvent(Object source, String message, Map<String, Object> data) {
    super(source);
    this.message = message;
    this.data = data;

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    if (auth == null) {
      this.principal = NULL_PRINCIPAL;
    } else {
      this.principal = auth.getName();
    }
  }

  public IamAuditApplicationEvent(Object source, String message) {
    this(source, message, Maps.newLinkedHashMap());
  }
  
  protected IamAuditApplicationEvent(Object source) {
    this(source, null, Maps.newLinkedHashMap());
  }

  public String getPrincipal() {
    return principal;
  }

  public String getMessage() {
    return message;
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
