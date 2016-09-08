package it.infn.mw.iam.config;

import java.util.Arrays;
import java.util.Collections;

import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.token.ChainedTokenGranter;
import org.mitre.oauth2.token.JWTAssertionTokenGranter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;

import it.infn.mw.iam.core.oauth.TokenExchangeTokenGranter;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

  @Autowired
  @Qualifier("iamUserDetailsService")
  private UserDetailsService iamUserDetailsService;

  @Autowired
  private OAuth2TokenEntityService tokenServices;

  @Autowired
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  private OAuth2RequestFactory requestFactory;

  @Autowired
  private AuthorizationCodeServices authorizationCodeServices;

  @Autowired
  private OAuth2RequestValidator requestValidator;

  @Autowired
  private UserApprovalHandler approvalHandler;

  @Bean
  WebResponseExceptionTranslator webResponseExceptionTranslator() {

    return new DefaultWebResponseExceptionTranslator();
  }

  @Bean(name = "authenticationManager")
  AuthenticationManager authenticationManager() {

    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(iamUserDetailsService);
    return new ProviderManager(Collections.<AuthenticationProvider>singletonList(provider));

  }

  @Bean
  public TokenGranter tokenGranter() {

    AuthenticationManager authenticationManager = authenticationManager();

    return new CompositeTokenGranter(Arrays.<TokenGranter>asList(
        new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices,
            clientDetailsService, requestFactory),
        new ImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new RefreshTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices,
            clientDetailsService, requestFactory),
        new JWTAssertionTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new ChainedTokenGranter(tokenServices, clientDetailsService, requestFactory),
        new TokenExchangeTokenGranter(tokenServices, clientDetailsService, requestFactory)));
  }

  @Override
  public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

    // @formatter:off
    endpoints.requestValidator(requestValidator).pathMapping("/oauth/token", "/token")
        .pathMapping("/oauth/authorize", "/authorize").tokenServices(tokenServices)
        .userApprovalHandler(approvalHandler).requestFactory(requestFactory)
        .tokenGranter(tokenGranter()).authorizationCodeServices(authorizationCodeServices);
    // @formatter:on
  }

  @Override
  public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {

    clients.withClientDetails(clientDetailsService);
  }

  @Override
  public void configure(final AuthorizationServerSecurityConfigurer security) throws Exception {

    security.allowFormAuthenticationForClients();

  }

}
