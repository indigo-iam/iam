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
import java.util.Objects;
import java.util.Set;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;

/**
 * <p>
 * An extended auth token that functions the same as a {@code UsernamePasswordAuthenticationToken}
 * but with some additional fields detailing more information about the methods of authentication
 * used.
 * 
 * <p>
 * The additional information includes:
 * 
 * <ul>
 * <li>{@code Set<AuthenticationMethodReferences} - details the methods of authentication used to
 * login. This is for providing the {@code amr} claim in an OAuth2 id_token provided to a
 * client</li>
 * <li>{@code String totp} - if authenticating with a TOTP, this field is set</li>
 * <li>{@code fullyAuthenticatedAuthorities} - the authorities the user will be granted if full
 * authentication takes place. If an MFA user has only authenticated with a username and password so
 * far, they will only officially have an authority of PRE_AUTHENTICATED
 * </ul>
 */
public class ExtendedAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 1L;
  private Object principal;
  private Object credentials;
  private Set<IamAuthenticationMethodReference> authenticationMethodReferences = new HashSet<>();
  private String totp;
  private Set<GrantedAuthority> fullyAuthenticatedAuthorities;
  private boolean preAuthenticated;

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

  public Set<GrantedAuthority> getFullyAuthenticatedAuthorities() {
    return fullyAuthenticatedAuthorities;
  }

  public void setFullyAuthenticatedAuthorities(
      Set<GrantedAuthority> fullyAuthenticatedAuthorities) {
    this.fullyAuthenticatedAuthorities = fullyAuthenticatedAuthorities;
  }

  public Set<IamAuthenticationMethodReference> getAuthenticationMethodReferences() {
    return authenticationMethodReferences;
  }

  public void setAuthenticationMethodReferences(
      Set<IamAuthenticationMethodReference> authenticationMethodReferences) {
    this.authenticationMethodReferences = authenticationMethodReferences;
  }

  public String getTotp() {
    return totp;
  }

  public void setTotp(String totp) {
    this.totp = totp;
  }

  @Override
  public Object getCredentials() {
    return this.credentials;
  }

  @Override
  public Object getPrincipal() {
    return this.principal;
  }

  public boolean isPreAuthenticated() {
    return preAuthenticated;
  }

  public void setPreAuthenticated(boolean generatedFromX509) {
    this.preAuthenticated = generatedFromX509;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof ExtendedAuthenticationToken)) {
      return false;
    }
    if (!super.equals(obj)) {
      return false;
    }
    ExtendedAuthenticationToken that = (ExtendedAuthenticationToken) obj;

    return Objects.equals(this.principal, that.principal)
        && Objects.equals(this.credentials, that.credentials)
        && Objects.equals(this.authenticationMethodReferences, that.authenticationMethodReferences)
        && Objects.equals(this.totp, that.totp)
        && Objects.equals(this.fullyAuthenticatedAuthorities, that.fullyAuthenticatedAuthorities);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), principal, credentials, authenticationMethodReferences,
        totp, fullyAuthenticatedAuthorities);
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
    sb.append("TOTP=").append(this.getTotp());
    sb.append("]");
    return sb.toString();
  }
}
