package it.infn.mw.iam.config;

import org.h2.server.web.WebServlet;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.embedded.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import it.infn.mw.iam.authn.oidc.OidcTokenEnhancer;
import it.infn.mw.iam.core.IamIntrospectionResultAssembler;
import it.infn.mw.iam.core.IamProperties;
import it.infn.mw.iam.util.DumpHeadersFilter;

@Configuration
public class IamConfig {

  @Value("${iam.organisation.name}")
  private String iamOrganisationName;

  @Bean
  AuthorizationCodeServices authorizationCodeServices() {

    return new DefaultOAuth2AuthorizationCodeService();
  }

  @Bean
  @Primary
  TokenEnhancer iamTokenEnhancer() {

    return new OidcTokenEnhancer();
  }

  @Bean
  IamProperties iamProperties() {

    IamProperties.INSTANCE.setOrganisationName(iamOrganisationName);
    return IamProperties.INSTANCE;
  }

  @Bean
  IntrospectionResultAssembler defaultIntrospectionResultAssembler() {

    return new IamIntrospectionResultAssembler();
  }

  @Bean
  @Profile("dev")
  ServletRegistrationBean h2Console() {

    WebServlet h2Servlet = new WebServlet();
    return new ServletRegistrationBean(h2Servlet, "/h2-console/*");
  }

  @Bean
  @Profile("dev")
  FilterRegistrationBean requestLoggingFilter() {

    DumpHeadersFilter dhf = new DumpHeadersFilter();

    dhf.setIncludeClientInfo(true);
    dhf.setIncludePayload(true);
    dhf.setIncludeQueryString(true);

    FilterRegistrationBean frb = new FilterRegistrationBean(dhf);
    frb.setOrder(0);
    return frb;
  }
}
