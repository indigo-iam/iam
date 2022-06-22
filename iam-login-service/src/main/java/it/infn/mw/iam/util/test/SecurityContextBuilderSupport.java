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
package it.infn.mw.iam.util.test;

import java.util.Date;
import java.util.List;

import org.joda.time.DateTime;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;

public abstract class SecurityContextBuilderSupport {

  protected String issuer;
  protected String subject;

  protected String username;

  protected Date expirationTime = DateTime.now().plusHours(1).toDate();

  protected List<GrantedAuthority> authorities;

  public SecurityContextBuilderSupport issuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public SecurityContextBuilderSupport subject(String subject) {
    this.subject = subject;
    return this;
  }

  public SecurityContextBuilderSupport username(String username) {
    this.username = username;
    return this;
  }

  public SecurityContextBuilderSupport authorities(String... authorities) {
    this.authorities = AuthorityUtils.createAuthorityList(authorities);
    return this;
  }

  public SecurityContextBuilderSupport authorities(List<GrantedAuthority> authorities) {
    this.authorities = authorities;
    return this;
  }

  public SecurityContextBuilderSupport expirationTime(long expirationTimeMillis) {
    if (expirationTimeMillis > 0) {
      this.expirationTime = new Date(expirationTimeMillis);
    }
    return this;
  }

  public abstract SecurityContextBuilderSupport email(String email);

  public abstract SecurityContextBuilderSupport name(String givenName, String familyName);

  public abstract SecurityContext buildSecurityContext();
}
