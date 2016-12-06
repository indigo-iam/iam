package it.infn.mw.iam.test.util;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_ROLE;
import static it.infn.mw.iam.test.ext_authn.saml.SamlExternalAuthenticationTestSupport.DEFAULT_IDP_ID;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.springframework.security.test.context.support.WithSecurityContext;

import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;
import it.infn.mw.iam.test.util.saml.WithSamlUserSecurityContextFactory;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithSamlUserSecurityContextFactory.class)
public @interface WithMockSAMLUser {
  String username() default "test-saml-user";

  String givenName() default "";

  String familyName() default "";

  String email() default "";

  String subject() default "test-saml-user";

  String subjectAttribute() default SamlAttributeNames.eduPersonUniqueId;

  String issuer() default DEFAULT_IDP_ID;

  String[] authorities() default {EXT_AUTHN_UNREGISTERED_USER_ROLE};

  long expirationTime() default -1;
}
