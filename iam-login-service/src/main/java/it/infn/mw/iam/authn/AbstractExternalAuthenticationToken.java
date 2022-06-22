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
package it.infn.mw.iam.authn;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;

import it.infn.mw.iam.persistence.model.IamAccount;

public abstract class AbstractExternalAuthenticationToken<T extends Serializable>
    extends ExpiringUsernameAuthenticationToken {

  /**
   * 
   */
  private static final long serialVersionUID = 3728054624371667370L;

  final T wrappedAuthentication;

  public AbstractExternalAuthenticationToken(T authn, Object principal, Object credentials) {
    super(principal, credentials);
    this.wrappedAuthentication = authn;

  }

  public AbstractExternalAuthenticationToken(T authn, Date tokenExpiration, Object principal,
      Object credentials, Collection<? extends GrantedAuthority> authorities) {
    super(tokenExpiration, principal, credentials, authorities);
    this.wrappedAuthentication = authn;
  }

  public T getExternalAuthentication() {
    return wrappedAuthentication;
  }

  public abstract Map<String, String> buildAuthnInfoMap();
  
  public abstract Map<String, String> buildAuthnInfoMap(ExternalAuthenticationInfoBuilder visitor);

  public abstract void linkToIamAccount(ExternalAccountLinker visitor, IamAccount account);

  public abstract ExternalAuthenticationRegistrationInfo toExernalAuthenticationRegistrationInfo();

  @Override
  public int hashCode() {
    int prime = 31;
    int result = super.hashCode();
    result =
        prime * result + ((wrappedAuthentication == null) ? 0 : wrappedAuthentication.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!super.equals(obj))
      return false;
    if (getClass() != obj.getClass())
      return false;
    @SuppressWarnings("rawtypes")
    AbstractExternalAuthenticationToken other = (AbstractExternalAuthenticationToken) obj;
    if (wrappedAuthentication == null) {
      if (other.wrappedAuthentication != null)
        return false;
    } else if (!wrappedAuthentication.equals(other.wrappedAuthentication))
      return false;
    return true;
  }
}
