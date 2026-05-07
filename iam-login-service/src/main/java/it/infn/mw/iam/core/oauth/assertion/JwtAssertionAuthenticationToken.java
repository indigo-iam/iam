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
package it.infn.mw.iam.core.oauth.assertion;

import java.text.ParseException;
import java.util.Collection;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.nimbusds.jwt.JWT;

public class JwtAssertionAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 1L;
  private String subject;
  private JWT jwt;

  public JwtAssertionAuthenticationToken(JWT jwt) throws ParseException {
    super(null);
    this.jwt = jwt;
    this.subject = jwt.getJWTClaimsSet().getSubject();
    setAuthenticated(false);
  }

  public JwtAssertionAuthenticationToken(JWT jwt,
      Collection<? extends GrantedAuthority> authorities) throws ParseException {
    super(authorities);
    this.jwt = jwt;
    this.subject = jwt.getJWTClaimsSet().getSubject();
    setAuthenticated(true);
  }

  @Override
  public Object getCredentials() {
    return jwt;
  }

  @Override
  public Object getPrincipal() {
    return subject;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.jwt = null;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(jwt, subject);
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
    JwtAssertionAuthenticationToken other = (JwtAssertionAuthenticationToken) obj;
    return Objects.equals(jwt.serialize(), other.jwt.serialize());
  }

}
