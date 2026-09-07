package it.infn.mw.voms;

import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.orm.jpa.JpaBaseConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.AbstractJpaVendorAdapter;
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.jta.JtaTransactionManager;

@TestConfiguration
@EnableTransactionManagement
public class VomsJpaTestConfig extends JpaBaseConfiguration {

  private final DataSource dataSource;

  protected VomsJpaTestConfig(DataSource dataSource, JpaProperties properties,
      ObjectProvider<JtaTransactionManager> jtaTransactionManager) {

    super(dataSource, properties, jtaTransactionManager);
    this.dataSource = dataSource;
  }

  @Override
  protected AbstractJpaVendorAdapter createJpaVendorAdapter() {
    return new EclipseLinkJpaVendorAdapter();
  }

  @Override
  protected Map<String, Object> getVendorProperties() {
    Map<String, Object> map = new HashMap<>();

    map.put("eclipselink.weaving", "false");
    map.put("eclipselink.logging.level", "WARNING");
    map.put("eclipselink.logging.level.sql", "OFF");
    map.put("eclipselink.cache.shared.default", "false");

    return map;
  }

  @Override
  public LocalContainerEntityManagerFactoryBean entityManagerFactory(
      EntityManagerFactoryBuilder factoryBuilder) {

    return factoryBuilder.dataSource(dataSource)
      .packages("it.infn.mw.iam.persistence")
      .persistenceUnit("defaultPersistenceUnit")
      .properties(getVendorProperties())
      .build();
  }

  @Bean(name = {"defaultTransactionManager", "transactionManager"})
  PlatformTransactionManager defaultTransactionManager() {
    return new JpaTransactionManager();
  }
}
