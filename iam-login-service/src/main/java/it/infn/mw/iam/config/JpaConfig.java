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

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.openid.connect.model.ApprovedSite;
import org.mitre.openid.connect.model.BlacklistedSite;
import org.mitre.openid.connect.model.WhitelistedSite;
import org.mitre.uma.model.Permission;
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

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupKey;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamAddress;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamExternalAuthenticationAttribute;
import it.infn.mw.iam.persistence.model.IamExternalAuthenticationDetails;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.IamNotificationReceiver;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamScopeMatchingPolicy;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.model.IamTokenExchangeScopePolicy;
import it.infn.mw.iam.persistence.model.IamTotpAdminKey;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.model.IamX509ProxyCertificate;

@Configuration
@EnableTransactionManagement
public class JpaConfig extends JpaBaseConfiguration {

  public static final String ECLIPSELINK_LOGGING_LEVEL = "eclipselink.logging.level";
  public static final String ECLIPSELINK_LOGGING_LEVEL_SQL = "eclipselink.logging.level.sql";
  public final IamProperties iamProperties;

  protected JpaConfig(DataSource dataSource, JpaProperties properties,
      ObjectProvider<JtaTransactionManager> jtaTransactionManager, IamProperties iamProperties) {
    super(dataSource, properties, jtaTransactionManager);
    this.iamProperties = iamProperties;
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

    if (iamProperties.isShowSql()) {
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

    return factoryBuilder
        .dataSource(dataSource)
        .persistenceUnit("defaultPersistenceUnit")
        .properties(getVendorProperties())
        .packages(
        ApprovedSite.class,
        AuthenticationHolderEntity.class,
        BlacklistedSite.class,
        ClientDetailsEntity.class,
        DeviceCode.class,
        OAuth2AccessTokenEntity.class,
        OAuth2RefreshTokenEntity.class,
        Permission.class,
        SystemScope.class,
        WhitelistedSite.class,
        IamAccount.class,
        IamAccountGroupKey.class,
        IamAccountGroupMembership.class,
        IamAddress.class,
        IamAttribute.class,
        IamAup.class,
        IamAupSignature.class,
        IamAuthority.class,
        IamClientMatchingPolicy.class,
        IamEmailNotification.class,
        IamExternalAuthenticationAttribute.class,
        IamExternalAuthenticationDetails.class,
        IamGroup.class,
        IamGroupRequest.class,
        IamLabel.class,
        IamNotificationReceiver.class,
        IamOidcId.class,
        IamRegistrationRequest.class,
        IamRevokedAccessToken.class,
        IamSamlId.class,
        IamScopeMatchingPolicy.class,
        IamScopePolicy.class,
        IamSshKey.class,
        IamTokenExchangePolicyEntity.class,
        IamTokenExchangeScopePolicy.class,
        IamTotpAdminKey.class,
        IamTotpMfa.class,
        IamUserInfo.class,
        IamX509Certificate.class,
        IamX509ProxyCertificate.class
      ).build();
  }

  @Bean(name = {"defaultTransactionManager", "transactionManager"})
  PlatformTransactionManager defaultTransactionManager() {

    return new JpaTransactionManager();
  }

  @Bean
  @Profile("no-flyway")
  FlywayMigrationStrategy flywayMigrationStrategy() {
    return f -> {
      // empty on purpose
    };
  }

  @Bean
  @Profile("flyway-repair")
  FlywayMigrationStrategy flywayRepairStrategy() {
    return f -> {
      f.repair();
      f.migrate();
    };
  }
}
