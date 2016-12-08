package it.infn.mw.iam.test.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;

import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@Configuration
public class CoreControllerTestSupport {

  @Primary
  @Bean(name = "resourceServerFilter")
  MockOAuth2Filter mockOAuth2Filter(OAuth2AuthenticationEntryPoint entryPoint) {

    return new MockOAuth2Filter();
  }
}
