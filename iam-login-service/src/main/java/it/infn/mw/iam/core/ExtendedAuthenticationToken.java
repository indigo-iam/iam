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
package it.infn.mw.iam.core;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;

public class ExtendedAuthenticationToken extends AbstractAuthenticationToken {

  private final Object principal;
  private Object credentials;
  private Set<IamAuthenticationMethodReference> authenticationMethodReferences = new HashSet<>();

  public ExtendedAuthenticationToken(Object principal, Object credentials) {
    super(null);
    this.principal = principal;
    this.credentials = credentials;
  }

  public ExtendedAuthenticationToken(Object principal, Object credentials,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.principal = principal;
    this.credentials = credentials;
  }

  public ExtendedAuthenticationToken(Object principal, Object credentials,
      Set<IamAuthenticationMethodReference> authenticationMethodReferences) {
    super(null);
    this.principal = principal;
    this.credentials = credentials;
    this.authenticationMethodReferences = authenticationMethodReferences;
  }

  public ExtendedAuthenticationToken(Object principal, Object credentials,
      Collection<? extends GrantedAuthority> authorities,
      Set<IamAuthenticationMethodReference> authenticationMethodReferences) {
    super(authorities);
    this.principal = principal;
    this.credentials = credentials;
    this.authenticationMethodReferences = authenticationMethodReferences;
  }

  public Set<IamAuthenticationMethodReference> getAuthenticationMethodReferences() {
    return authenticationMethodReferences;
  }

  public void setAuthenticationMethodReferences(
      Set<IamAuthenticationMethodReference> authenticationMethodReferences) {
    this.authenticationMethodReferences = authenticationMethodReferences;
  }

  @Override
  public Object getCredentials() {
    return this.credentials;
  }

  @Override
  public Object getPrincipal() {
    return this.principal;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(getClass().getSimpleName()).append(" [");
    sb.append("Principal=").append(getPrincipal()).append(", ");
    sb.append("Credentials=[PROTECTED], ");
    sb.append("Authenticated=").append(isAuthenticated()).append(", ");
    sb.append("Details=").append(getDetails()).append(", ");
    sb.append("Granted Authorities=").append(this.getAuthorities()).append(", ");
    sb.append("Authentication Method References=").append(this.getAuthenticationMethodReferences());
    sb.append("]");
    return sb.toString();
  }
}
