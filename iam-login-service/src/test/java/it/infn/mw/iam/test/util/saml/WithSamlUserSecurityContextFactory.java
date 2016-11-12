package it.infn.mw.iam.test.util.saml;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import it.infn.mw.iam.test.util.WithMockSAMLUser;

public class WithSamlUserSecurityContextFactory
    implements WithSecurityContextFactory<WithMockSAMLUser> {

  @Override
  public SecurityContext createSecurityContext(WithMockSAMLUser annotation) {

    SamlSecurityContextBuilder builder = new SamlSecurityContextBuilder();

    builder.subject(annotation.subject())
      .issuer(annotation.issuer())
      .authorities(annotation.authorities())
      .email(annotation.email())
      .username(annotation.username())
      .name(annotation.givenName(), annotation.familyName())
      .expirationTime(annotation.expirationTime());

    return builder.buildSecurityContext();
  }

}
