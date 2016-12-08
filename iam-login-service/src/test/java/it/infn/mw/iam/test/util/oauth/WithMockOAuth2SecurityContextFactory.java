package it.infn.mw.iam.test.util.oauth;

import java.util.Map;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import com.google.common.collect.Maps;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

public class WithMockOAuth2SecurityContextFactory
    implements WithSecurityContextFactory<WithMockOAuthUser> {

  final MockOAuth2Filter filter;

  @Autowired
  public WithMockOAuth2SecurityContextFactory(MockOAuth2Filter filter) {
    this.filter = filter;
  }

  private Authentication buildExternalUserAuthentication(WithMockOAuthUser annotation) {

    SavedUserAuthentication userAuth = new SavedUserAuthentication();

    userAuth.setAuthenticated(true);
    userAuth.setAuthorities(AuthorityUtils.createAuthorityList(annotation.authorities()));
    userAuth.setName(annotation.user());
    Map<String, String> additionalInfo = Maps.newHashMap();

    if (annotation.externalAuthenticationType().equals(ExternalAuthenticationType.OIDC)) {
      userAuth.setSourceClass(OidcExternalAuthenticationToken.class.getName());

      additionalInfo.put("type", "oidc");
      additionalInfo.put("sub", "sub");
      additionalInfo.put("iss", "iss");

      userAuth.setAdditionalInfo(additionalInfo);

    } else {

      userAuth.setSourceClass(SamlExternalAuthenticationToken.class.getName());
      additionalInfo.put("type", "saml");
      additionalInfo.put("epuid", "epuid");
      additionalInfo.put("ipdId", "idpid");
    }

    return userAuth;
  }

  private Authentication buildUserAuthentication(WithMockOAuthUser annotation) {

    if (annotation.externallyAuthenticated()) {
      return buildExternalUserAuthentication(annotation);
    }

    return new UsernamePasswordAuthenticationToken(annotation.user(), "",
        AuthorityUtils.createAuthorityList(annotation.authorities()));
  }

  @Override
  public SecurityContext createSecurityContext(WithMockOAuthUser annotation) {

    SecurityContext context = SecurityContextHolder.createEmptyContext();

    Authentication userAuthn = null;

    if (!annotation.user().equals("")) {

      userAuthn = buildUserAuthentication(annotation);
    }

    OAuth2Authentication authn = new OAuth2Authentication(
        new MockOAuth2Request(annotation.clientId(), annotation.scopes()), userAuthn);

    authn.setAuthenticated(true);

    authn.setDetails("No details");
    context.setAuthentication(authn);

    filter.setSecurityContext(context);
    return context;
  }

}
