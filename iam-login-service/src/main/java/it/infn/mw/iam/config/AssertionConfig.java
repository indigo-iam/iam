package it.infn.mw.iam.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.mitre.jwt.assertion.AssertionValidator;
import org.mitre.jwt.assertion.impl.NullAssertionValidator;
import org.mitre.jwt.assertion.impl.WhitelistedIssuerAssertionValidator;
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory;
import org.mitre.oauth2.assertion.impl.DirectCopyRequestFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AssertionConfig {

  @Bean
  @Qualifier("jwtAssertionValidator")
  public AssertionValidator jwtAssertionValidator() {
    return new NullAssertionValidator();
  }

  @Bean
  @Qualifier("jwtAssertionTokenFactory")
  public AssertionOAuth2RequestFactory jwtAssertionTokenFactory() {
    return new DirectCopyRequestFactory();
  }

  @Bean
  @Qualifier("clientAssertionValidator")
  public AssertionValidator clientAssertionValidator() {
    // TODO: verify whitelist
    Map<String, String> whitelist = new LinkedHashMap<>();
    whitelist.put("http://artemesia.local", "http://localhost:8080/jwk");

    WhitelistedIssuerAssertionValidator validator = new WhitelistedIssuerAssertionValidator();
    validator.setWhitelist(whitelist);

    return validator;
  }
}
