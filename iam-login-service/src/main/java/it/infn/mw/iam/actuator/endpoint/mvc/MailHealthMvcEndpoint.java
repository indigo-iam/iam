package it.infn.mw.iam.actuator.endpoint.mvc;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.util.Collection;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.endpoint.mvc.AbstractEndpointMvcAdapter;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.common.collect.Maps;

import it.infn.mw.iam.actuator.endpoint.MailHealthEndpoint;

@Component
@ConfigurationProperties(prefix = "endpoints.healthMail")
public class MailHealthMvcEndpoint extends AbstractEndpointMvcAdapter<MailHealthEndpoint> {

  private Map<String, HttpStatus> statusMapping = Maps.newLinkedHashMap();

  @Autowired
  public MailHealthMvcEndpoint(MailHealthEndpoint delegate) {
    super(delegate);
    statusMapping.put("DOWN", HttpStatus.SERVICE_UNAVAILABLE);
  }

  @RequestMapping(produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public Object getMailHealth(AbstractAuthenticationToken auth) {
    if (!getDelegate().isEnabled()) {
      return getDisabledResponse();
    }

    Health health = getHealth(auth);
    HttpStatus status = getStatus(health);

    if (status != null) {
      return new ResponseEntity<Health>(health, status);
    }

    return health;
  }


  private HttpStatus getStatus(Health health) {
    return statusMapping.get(health.getStatus().getCode());
  }

  private Health getHealth(AbstractAuthenticationToken auth) {
    Health health = getDelegate().invoke();

    if (auth != null && isAdmin(auth.getAuthorities())) {
      return health;
    }
    return Health.status(health.getStatus()).build();
  }

  private boolean isAdmin(Collection<GrantedAuthority> authorities) {
    for (GrantedAuthority authority : authorities) {
      if ("ROLE_ADMIN".equals(authority.getAuthority())) {
        return true;
      }
    }
    return false;
  }

}
