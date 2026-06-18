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

import java.util.HashMap;
import java.util.Map;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;

@SuppressWarnings("deprecation")
@Component
public class MockOAuthSecurityContextService {

  private final MockOAuth2Filter filter;

  @Autowired
  public MockOAuthSecurityContextService(MockOAuth2Filter filter) {
    this.filter = filter;
  }

  public void authenticate(
      String clientId,
      String user,
      String[] scopes,
      String[] authorities,
      boolean externallyAuthenticated,
      ExternalAuthenticationType externalType
  ) {
    SecurityContext context = SecurityContextHolder.createEmptyContext();

    Authentication userAuth;
    if (externallyAuthenticated) {
      userAuth = buildExternalUser(user, authorities, externalType);
    } else {
      userAuth = new UsernamePasswordAuthenticationToken(
          user, "", AuthorityUtils.createAuthorityList(authorities));
    }

    OAuth2Authentication auth =
        new OAuth2Authentication(new MockOAuth2Request(clientId, scopes), userAuth);

    auth.setAuthenticated(true);
    context.setAuthentication(auth);

    filter.setSecurityContext(context);
    SecurityContextHolder.setContext(context);
  }

  public void clear() {
    filter.cleanupSecurityContext();
  }

  private Authentication buildExternalUser(
      String user, String[] authorities, ExternalAuthenticationType type) {

    SavedUserAuthentication auth = new SavedUserAuthentication();
    auth.setAuthenticated(true);
    auth.setName(user);
    auth.setAuthorities(AuthorityUtils.createAuthorityList(authorities));

    Map<String, String> info = new HashMap<>();
    if (type == ExternalAuthenticationType.OIDC) {
      auth.setSourceClass(OidcExternalAuthenticationToken.class.getName());
      info.put("type", "oidc");
      info.put("sub", "sub");
      info.put("iss", "iss");
    } else {
      auth.setSourceClass(SamlExternalAuthenticationToken.class.getName());
      info.put("type", "saml");
      info.put("EPUID", "EPUID");
      info.put("idpid", "idpid");
    }
    auth.setAdditionalInfo(info);
    return auth;
  }
}