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
package it.infn.mw.iam;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.h2.H2ConsoleAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import java.net.ConnectException;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.flywaydb.core.internal.exception.FlywaySqlException;

import it.infn.mw.iam.core.util.IamBanner;
import it.infn.mw.iam.jwkfallback.FallbackShutdownSignal;

@SpringBootApplication
@EnableTransactionManagement
// @formatter:off
@ComponentScan(basePackages = {
    "it.infn.mw.iam.config", 
    "it.infn.mw.iam.authn",
    "it.infn.mw.iam.persistence", 
    "it.infn.mw.iam.core",
    "it.infn.mw.iam.api", 
    "it.infn.mw.iam.registration", 
    "it.infn.mw.iam.dashboard",
    "it.infn.mw.iam.notification",
    "it.infn.mw.iam.audit",
    "it.infn.mw.iam.actuator",
    "it.infn.mw.iam.rcauth",
    "it.infn.mw.iam.service.aup"})
@EnableCaching
@EnableAutoConfiguration(
    exclude = {
        SecurityAutoConfiguration.class,
        H2ConsoleAutoConfiguration.class
})
//@formatter:on
public class IamLoginService {

  public static void main(final String[] args) {

    SpringApplication iamLoginService = new SpringApplication(IamLoginService.class);

    AtomicReference<ConfigurableEnvironment> environmentRef = new AtomicReference<>();
    iamLoginService.addListeners(
        (ApplicationListener<ApplicationEnvironmentPreparedEvent>) event -> environmentRef.set(event.getEnvironment()));
    iamLoginService.setBanner(new IamBanner(new ClassPathResource("iam-banner.txt")));
    iamLoginService.addListeners(new ApplicationFailedEventListener());

    // Attempting to run the IAM
    try {
      iamLoginService.run(args);
    } catch (BeanCreationException e) {

      int indexOfconnectionException = ExceptionUtils.indexOfThrowable(e, ConnectException.class);
      int indexOfFlyWay = ExceptionUtils.indexOfThrowable(e, FlywaySqlException.class);
      boolean fallbackEnabled = environmentRef.get().getProperty("iam.jwk.standalone-fallback-enabled", Boolean.class,
          false);

      // Checking if the error is a database connection issue
      if (indexOfconnectionException != -1 && indexOfFlyWay != -1 && fallbackEnabled) {
        System.err.println("Connection exception in the db, sucks to be you, huh");

        // Starting the fallback application
        startFallBackApplication(args);
      }
    }
  }

  @Bean
  static PropertySourcesPlaceholderConfigurer iamPropertiesPlaceholderConfigurer() {
    PropertySourcesPlaceholderConfigurer propsConfig = new PropertySourcesPlaceholderConfigurer();

    propsConfig.setLocations(new ClassPathResource("iam.version.properties"),
        new ClassPathResource("git.properties"));

    propsConfig.setIgnoreResourceNotFound(true);
    propsConfig.setIgnoreUnresolvablePlaceholders(true);

    return propsConfig;
  }

  private static void startFallBackApplication(final String[] args) {

    // Starting the fallback application
    FallbackShutdownSignal shutdownSignal = new FallbackShutdownSignal();
    SpringApplication fallback = new SpringApplication(IamJwkFallbackApplication.class);
    fallback.setBannerMode(org.springframework.boot.Banner.Mode.OFF);
    fallback.addInitializers(context -> context.getBeanFactory().registerSingleton(
        "fallbackShutdownSignal", shutdownSignal));

    try (ConfigurableApplicationContext fallbackContext = fallback.run(args)) {

      // Awaiting the shutdown before closing
      // indicating the database connection has been restored
      shutdownSignal.awaitStopped();

    } catch (InterruptedException error2) {
      Thread.currentThread().interrupt();
      return;
    }
  }
}
