/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.config;

import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.boot.autoconfigure.orm.jpa.JpaBaseConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.AbstractJpaVendorAdapter;
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.jta.JtaTransactionManager;

@Configuration
@EnableTransactionManagement
public class JpaConfig extends JpaBaseConfiguration {

  public static final String ECLIPSELINK_LOGGING_LEVEL = "eclipselink.logging.level";
  public static final String ECLIPSELINK_LOGGING_LEVEL_SQL = "eclipselink.logging.level.sql";

  protected JpaConfig(DataSource dataSource, JpaProperties properties,
      ObjectProvider<JtaTransactionManager> jtaTransactionManager) {
    super(dataSource, properties, jtaTransactionManager);
  }

  @Autowired
  DataSource dataSource;

  @Override
  protected AbstractJpaVendorAdapter createJpaVendorAdapter() {

    return new EclipseLinkJpaVendorAdapter();
  }

  @Override
  protected Map<String, Object> getVendorProperties() {

    Map<String, Object> map = new HashMap<>();

    map.put("eclipselink.weaving", "false");
    map.put(ECLIPSELINK_LOGGING_LEVEL, "WARNING");
    map.put(ECLIPSELINK_LOGGING_LEVEL_SQL, "OFF");
    map.put("eclipselink.cache.shared.default", "false");

    if (System.getProperty("iam.show_sql") != null) {
      map.put(ECLIPSELINK_LOGGING_LEVEL, "FINE");
      map.put(ECLIPSELINK_LOGGING_LEVEL_SQL, "FINE");
      map.put("eclipselink.logging.parameters", "true");
    }

    if (System.getProperty("iam.generate-ddl-sql-script") != null) {
      map.put(ECLIPSELINK_LOGGING_LEVEL, "FINE");
      map.put("eclipselink.ddl-generation.output-mode", "sql-script");
      map.put("eclipselink.ddl-generation", "create-tables");
      map.put("eclipselink.create-ddl-jdbc-file-name", "ddl.sql");
    }

    return map;

  }

  @Override
  public LocalContainerEntityManagerFactoryBean entityManagerFactory(

      final EntityManagerFactoryBuilder factoryBuilder) {

    return factoryBuilder.dataSource(dataSource)
      .packages("org.mitre", "it.infn.mw.iam.persistence")
      .persistenceUnit("defaultPersistenceUnit")
      .properties(getVendorProperties())
      .build();

  }

  @Bean(name = {"defaultTransactionManager", "transactionManager"})
  public PlatformTransactionManager defaultTransactionManager() {

    return new JpaTransactionManager();
  }

  @Bean
  @Profile("no-flyway")
  public FlywayMigrationStrategy flywayMigrationStrategy() {
    return f -> {
      //  empty on purpose
    }; 
  }

  @Bean
  @Profile("flyway-repair")
  public FlywayMigrationStrategy flywayRepairStrategy() {
    return f -> {
      f.repair();
      f.migrate();
    };
  }
}
