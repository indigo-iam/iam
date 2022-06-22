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
package it.infn.mw.iam.authn.util;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AuthenticationUtils {

  private static final Set<String> SUPPORTED_EXTERNAL_AUTHN_TOKENS =
      Set.of(SamlExternalAuthenticationToken.class.getName(),
          OidcExternalAuthenticationToken.class.getName());

  private AuthenticationUtils() {}
  
  public static boolean isSupportedExternalAuthenticationToken(Authentication authn) {

    if (authn instanceof SavedUserAuthentication) {
      SavedUserAuthentication savedAuth = (SavedUserAuthentication) authn;

      if (savedAuth.getSourceClass() != null) {
        return SUPPORTED_EXTERNAL_AUTHN_TOKENS.contains(savedAuth.getSourceClass());
      }

    }
    return false;
  }

  public static List<GrantedAuthority> convertIamAccountAuthorities(IamAccount account) {
    return account.getAuthorities()
      .stream()
      .map(a -> new SimpleGrantedAuthority(a.getAuthority()))
      .collect(Collectors.toList());
  }
  
  public static User userFromIamAccount(IamAccount account){
    return new User(account.getUsername(), account.getPassword(), convertIamAccountAuthorities(account));
  }

  

}
