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
package it.infn.mw.iam.authn.jwt;

import java.text.ParseException;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.nimbusds.jwt.JWT;

public class JwtBearerAssertionAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = -3138213539914074617L;

  private String subject;
  private JWT jwt;

  public JwtBearerAssertionAuthenticationToken(JWT jwt) {
    this(jwt, null);
  }

  public JwtBearerAssertionAuthenticationToken(JWT jwt,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    try {
      this.subject = jwt.getJWTClaimsSet().getSubject();
    } catch (ParseException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
    this.jwt = jwt;
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

  public JWT getJwt() {
    return jwt;
  }

  public void setJwt(JWT jwt) {
    this.jwt = jwt;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    setJwt(null);
  }
}

