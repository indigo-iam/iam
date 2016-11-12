package it.infn.mw.iam.test.util;

import static it.infn.mw.iam.authn.ExternalAuthenticationSuccessHandler.EXT_AUTHN_UNREGISTERED_USER_ROLE;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.springframework.security.test.context.support.WithSecurityContext;

import it.infn.mw.iam.test.util.oidc.WithMockOIDCUserSecurityContextFactory;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockOIDCUserSecurityContextFactory.class)
public @interface WithMockOIDCUser {

  String username() default "test-oidc-user";

  String givenName() default "";

  String familyName() default "";

  String email() default "";

  String subject() default "test-oidc-user";

  String issuer() default "test-oidc-issuer";

  String[] authorities() default {EXT_AUTHN_UNREGISTERED_USER_ROLE};

  long expirationTime() default -1;
}
