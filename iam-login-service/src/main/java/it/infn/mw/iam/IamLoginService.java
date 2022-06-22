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

import org.mitre.discovery.web.DiscoveryEndpoint;
import org.mitre.oauth2.web.CorsFilter;
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint;
import org.mitre.openid.connect.web.JWKSetPublishingEndpoint;
import org.mitre.oauth2.web.OAuthConfirmationController;
import org.mitre.openid.connect.web.RootController;
import org.mitre.openid.connect.web.UserInfoEndpoint;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.h2.H2ConsoleAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import it.infn.mw.iam.core.util.IamBanner;

@SpringBootApplication
@EnableTransactionManagement

// @formatter:off
@ComponentScan(basePackages = {
    "it.infn.mw.iam.config", 
    "it.infn.mw.iam.authn",
    "it.infn.mw.iam.persistence", 
    "it.infn.mw.iam.core",
    "it.infn.mw.iam.core.oauth.scope",
    "it.infn.mw.iam.api", 
    "it.infn.mw.iam.registration", 
    "it.infn.mw.iam.dashboard",
    "it.infn.mw.iam.notification",
    "it.infn.mw.iam.audit",
    "it.infn.mw.iam.actuator",
    "it.infn.mw.iam.rcauth",
    "org.mitre.oauth2.web",
    "org.mitre.oauth2.view", 
    "org.mitre.openid.connect.web", 
    "org.mitre.openid.connect.view",
    "org.mitre.discovery.web", 
    "org.mitre.discovery.view"},
excludeFilters = {
    @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,
        value=UserInfoEndpoint.class),
    @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,
        value=RootController.class),
    @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,
        value=DiscoveryEndpoint.class),
    @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,
        value=JWKSetPublishingEndpoint.class),
    @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,
        value=DynamicClientRegistrationEndpoint.class),
    @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,
        value=CorsFilter.class),
    @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE,
        value=OAuthConfirmationController.class)
})

@EnableAutoConfiguration(
    exclude = {
        SecurityAutoConfiguration.class,
        H2ConsoleAutoConfiguration.class
})
//@formatter:on
public class IamLoginService {

  public static void main(final String[] args) {
    SpringApplication iamLoginService = new SpringApplication(IamLoginService.class);
    iamLoginService.setBanner(new IamBanner(new ClassPathResource("iam-banner.txt")));
    iamLoginService.run(args);

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
}
