package it.infn.mw.iam.test.ext_authn.oidc;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;

@Configuration
public class FullyMockedOidcClientConfiguration {

  @Bean
  @Primary
  public OidcTokenRequestor tokenRequestor(MockOIDCProvider mockOidcProvider) {
    return mockOidcProvider;
  }

}
