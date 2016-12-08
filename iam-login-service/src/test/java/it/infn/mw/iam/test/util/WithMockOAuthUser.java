package it.infn.mw.iam.test.util;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.springframework.security.test.context.support.WithSecurityContext;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.test.util.oauth.WithMockOAuth2SecurityContextFactory;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockOAuth2SecurityContextFactory.class)
public @interface WithMockOAuthUser {

  String clientId() default "password-grant";

  String user() default "";

  String[] scopes() default {};

  String[] authorities() default {};

  boolean externallyAuthenticated() default false;

  ExternalAuthenticationType externalAuthenticationType() default ExternalAuthenticationType.OIDC;
}
