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
import java.util.Optional;
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

  private AuthenticationUtils() {}

  public static Optional<SavedUserAuthentication> getExternalAuthenticationInfo(
      Authentication authn) {

    if (authn instanceof SavedUserAuthentication savedAuth
        && (isExternalOidcAuthentication(savedAuth) || isExternalSamlAuthentication(savedAuth))) {
      return Optional.ofNullable(savedAuth);
    }
    return Optional.empty();
  }

  public static boolean isExternalOidcAuthentication(SavedUserAuthentication userAuth) {
    return OidcExternalAuthenticationToken.class.getName().equals(userAuth.getSourceClass());
  }

  public static boolean isExternalSamlAuthentication(SavedUserAuthentication userAuth) {
    return SamlExternalAuthenticationToken.class.getName().equals(userAuth.getSourceClass());
  }

  public static List<GrantedAuthority> convertIamAccountAuthorities(IamAccount account) {
    return account.getAuthorities()
      .stream()
      .map(a -> new SimpleGrantedAuthority(a.getAuthority()))
      .collect(Collectors.toList());
  }

  public static User userFromIamAccount(IamAccount account) {
    return new User(account.getUsername(), account.getPassword(),
        convertIamAccountAuthorities(account));
  }



}
