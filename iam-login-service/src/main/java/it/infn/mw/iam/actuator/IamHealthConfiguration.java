package it.infn.mw.iam.actuator;

import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.endpoint.HealthEndpoint;
import org.springframework.boot.actuate.health.DataSourceHealthIndicator;
import org.springframework.boot.actuate.health.DiskSpaceHealthIndicator;
import org.springframework.boot.actuate.health.DiskSpaceHealthIndicatorProperties;
import org.springframework.boot.actuate.health.HealthAggregator;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.OrderedHealthAggregator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class IamHealthConfiguration {

  @Autowired(required = false)
  private HealthAggregator healthAggregator = new OrderedHealthAggregator();

  @Autowired
  DataSource dataSource;

  @Autowired
  DiskSpaceHealthIndicatorProperties properties;

  @Bean
  public HealthEndpoint healthEndpoint() {
    Map<String, HealthIndicator> healthIndicators = new HashMap<>();

    healthIndicators.put("db", new DataSourceHealthIndicator(dataSource));
    healthIndicators.put("diskSpace", new DiskSpaceHealthIndicator(properties));

    return new HealthEndpoint(this.healthAggregator, healthIndicators);
  }

}
