package it.infn.mw.iam;

import org.mitre.openid.connect.web.RootController;
import org.mitre.openid.connect.web.UserInfoEndpoint;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.h2.H2ConsoleAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.OAuth2AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import it.infn.mw.iam.core.IamBanner;

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
})
// @formatter:on

@EnableAutoConfiguration(exclude = {SecurityAutoConfiguration.class, OAuth2AutoConfiguration.class,
    H2ConsoleAutoConfiguration.class})
public class IamLoginService {

  public static void main(final String[] args) {
    SpringApplication iamLoginService = new SpringApplication(IamLoginService.class);

    iamLoginService.setBanner(new IamBanner(new ClassPathResource("iam-banner.txt")));

    iamLoginService.run(args);

  }

  @Bean
  static PropertySourcesPlaceholderConfigurer iamVersionPlaceholderConfigurer() {
    PropertySourcesPlaceholderConfigurer propsConfig = new PropertySourcesPlaceholderConfigurer();

    propsConfig.setLocation(new ClassPathResource("iam.version.properties"));
    propsConfig.setIgnoreResourceNotFound(true);
    propsConfig.setIgnoreUnresolvablePlaceholders(true);

    return propsConfig;
  }


  @Bean
  static PropertySourcesPlaceholderConfigurer gitCommitPlaceholderConfigurer() {
    PropertySourcesPlaceholderConfigurer propsConfig = new PropertySourcesPlaceholderConfigurer();

    propsConfig.setLocation(new ClassPathResource("git.properties"));
    propsConfig.setIgnoreResourceNotFound(true);
    propsConfig.setIgnoreUnresolvablePlaceholders(true);

    return propsConfig;
  }
}
