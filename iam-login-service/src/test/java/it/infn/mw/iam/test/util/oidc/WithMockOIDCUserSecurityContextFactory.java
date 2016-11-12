package it.infn.mw.iam.test.util.oidc;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import it.infn.mw.iam.test.util.WithMockOIDCUser;

public class WithMockOIDCUserSecurityContextFactory
    implements WithSecurityContextFactory<WithMockOIDCUser> {

  @Override
  public SecurityContext createSecurityContext(WithMockOIDCUser annotation) {

    OidcSecurityContextBuilder builder = new OidcSecurityContextBuilder();

    return builder.issuer(annotation.issuer())
      .subject(annotation.subject())
      .email(annotation.email())
      .name(annotation.givenName(), annotation.familyName())
      .username(annotation.username())
      .authorities(annotation.authorities())
      .expirationTime(annotation.expirationTime())
      .buildSecurityContext();
  }


}
