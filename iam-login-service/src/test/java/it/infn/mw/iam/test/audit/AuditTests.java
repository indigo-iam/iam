package it.infn.mw.iam.test.audit;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.util.Collections;

import javax.transaction.Transactional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.audit.IamAuditEventLogger;
import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.auth.IamAuthenticationFailureEvent;
import it.infn.mw.iam.audit.events.auth.IamAuthenticationSuccessEvent;
import it.infn.mw.iam.audit.events.auth.IamAuthorizationFailureEvent;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class})
@WebAppConfiguration
@Transactional
public class AuditTests {

  @Autowired
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  private IamAuditEventLogger logger;

  @Test
  @WithMockUser(username = "admin", password = "bad_password")
  public void testAuthenticationFailureBadCredentialsEvent() throws Exception {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    BadCredentialsException e = new BadCredentialsException("Bad credentials test");

    eventPublisher.publishEvent(new AuthenticationFailureBadCredentialsEvent(auth, e));

    IamAuditApplicationEvent ev = logger.getLastEvent();

    assertNotNull(ev);
    assertThat(ev, is(instanceOf(IamAuthenticationFailureEvent.class)));

  }

  @Test
  @WithMockUser(username = "admin", password = "password")
  public void testInteractiveAuthenticationSuccessEvent() throws Exception {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(auth, this.getClass()));

    IamAuditApplicationEvent ev = logger.getLastEvent();

    assertNotNull(ev);
    assertThat(ev, is(instanceOf(IamAuthenticationSuccessEvent.class)));

  }

  @Test
  public void testAuthorizationFailureEvent() throws Exception {

    AuthorizationFailureEvent event = new AuthorizationFailureEvent(this,
        Collections.<ConfigAttribute>singletonList(new SecurityConfig("USER")),
        new UsernamePasswordAuthenticationToken("user", "password"),
        new AccessDeniedException("Bad user"));

    eventPublisher.publishEvent(event);

    IamAuditApplicationEvent ev = logger.getLastEvent();

    assertNotNull(ev);
    assertThat(ev, is(instanceOf(IamAuthorizationFailureEvent.class)));
  }
}
