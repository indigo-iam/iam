package it.infn.mw.iam.actuator.endpoint;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.endpoint.AbstractEndpoint;
import org.springframework.boot.actuate.health.CompositeHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthAggregator;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.MailHealthIndicator;
import org.springframework.boot.actuate.health.OrderedHealthAggregator;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "endpoints.healthMail")
public class MailHealthEndpoint extends AbstractEndpoint<Health> {

  public static final String ENDPOINT_ID = "healthMail";

  private final HealthIndicator healthIndicator;

  @Autowired
  private HealthAggregator healthAggregator = new OrderedHealthAggregator();

  @Autowired
  public MailHealthEndpoint(JavaMailSenderImpl mailSender) {
    super(ENDPOINT_ID, false);

    CompositeHealthIndicator indicator = new CompositeHealthIndicator(healthAggregator);
    indicator.addHealthIndicator("mail", new MailHealthIndicator(mailSender));

    this.healthIndicator = indicator;
  }

  @Override
  public Health invoke() {
    return this.healthIndicator.health();
  }

}
