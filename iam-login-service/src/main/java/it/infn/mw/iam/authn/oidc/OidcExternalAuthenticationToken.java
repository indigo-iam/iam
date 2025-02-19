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
package it.infn.mw.iam.authn.oidc;

import static it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder.OIDC_TYPE;
import static it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoBuilder.TYPE_ATTR;
import static it.infn.mw.iam.authn.util.JwtUtils.getClaimsAsMap;
import static java.util.Objects.isNull;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.google.common.collect.Maps;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.core.CommonAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;

public class OidcExternalAuthenticationToken
    extends AbstractExternalAuthenticationToken<OIDCAuthenticationToken>
    implements CommonAuthenticationToken {

  private static final long serialVersionUID = -1297301102973236138L;

  private Object principal;
  private Object credentials;
  private Set<IamAuthenticationMethodReference> authenticationMethodReferences = new HashSet<>();
  private String totp;
  private Set<GrantedAuthority> fullyAuthenticatedAuthorities;

  public OidcExternalAuthenticationToken(OIDCAuthenticationToken authn, Object principal,
      Object credentials) {
    super(authn, principal, credentials);
    this.principal = principal;
    this.credentials = credentials;
  }

  public OidcExternalAuthenticationToken(OIDCAuthenticationToken authn, Date tokenExpiration,
      Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
    super(authn, tokenExpiration, principal, credentials, authorities);
    this.principal = principal;
    this.credentials = credentials;
  }

  @Override
  public Set<GrantedAuthority> getFullyAuthenticatedAuthorities() {
    return fullyAuthenticatedAuthorities;
  }

  @Override
  public void setFullyAuthenticatedAuthorities(
      Set<GrantedAuthority> fullyAuthenticatedAuthorities) {
    this.fullyAuthenticatedAuthorities = fullyAuthenticatedAuthorities;
  }

  @Override
  public Set<IamAuthenticationMethodReference> getAuthenticationMethodReferences() {
    return authenticationMethodReferences;
  }

  @Override
  public void setAuthenticationMethodReferences(
      Set<IamAuthenticationMethodReference> authenticationMethodReferences) {
    this.authenticationMethodReferences = authenticationMethodReferences;
  }

  @Override
  public String getTotp() {
    return totp;
  }

  @Override
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

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof OidcExternalAuthenticationToken)) {
      return false;
    }
    if (!super.equals(obj)) {
      return false;
    }
    OidcExternalAuthenticationToken that = (OidcExternalAuthenticationToken) obj;

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

  @Override
  public Map<String, String> buildAuthnInfoMap(ExternalAuthenticationInfoBuilder visitor) {
    return visitor.buildInfoMap(this);
  }

  @Override
  public ExternalAuthenticationRegistrationInfo toExernalAuthenticationRegistrationInfo() {
    ExternalAuthenticationRegistrationInfo ri =
        new ExternalAuthenticationRegistrationInfo(ExternalAuthenticationType.OIDC);

    ri.setAdditionalAttributes(Maps.newHashMap());
    ri.setSubject(getExternalAuthentication().getSub());
    ri.setIssuer(getExternalAuthentication().getIssuer());

    if (getExternalAuthentication().getUserInfo() != null) {
      ri.setEmail(getExternalAuthentication().getUserInfo().getEmail());
      ri.setGivenName(getExternalAuthentication().getUserInfo().getGivenName());
      ri.setFamilyName(getExternalAuthentication().getUserInfo().getFamilyName());
      ri.setSuggestedUsername(getExternalAuthentication().getUserInfo().getPreferredUsername());
    }

    ri.getAdditionalAttributes().putAll(buildAuthnInfoMap());
    return ri;
  }

  @Override
  public void linkToIamAccount(ExternalAccountLinker visitor, IamAccount account) {
    visitor.linkToIamAccount(account, this);
  }

  @Override
  public Map<String, String> buildAuthnInfoMap() {
    Map<String, String> infoMap = new HashMap<>();

    infoMap.put(TYPE_ATTR, OIDC_TYPE);
    infoMap.put("sub", getExternalAuthentication().getSub());
    infoMap.put("iss", getExternalAuthentication().getIssuer());

    if (!isNull(getExternalAuthentication().getIdToken())) {
      infoMap.putAll(getClaimsAsMap(getExternalAuthentication().getIdToken()));
    }

    return infoMap;
  }
}
