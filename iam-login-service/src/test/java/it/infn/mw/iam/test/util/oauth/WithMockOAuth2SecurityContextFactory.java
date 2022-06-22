/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.util.oauth;

import java.util.Map;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import com.google.common.collect.Maps;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

@SuppressWarnings("deprecation")
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
      additionalInfo.put("EPUID", "EPUID");
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

    OAuth2AuthenticationDetails details = Mockito.mock(OAuth2AuthenticationDetails.class);

    authn.setDetails(details);
    context.setAuthentication(authn);

    filter.setSecurityContext(context);
    return context;
  }

}
