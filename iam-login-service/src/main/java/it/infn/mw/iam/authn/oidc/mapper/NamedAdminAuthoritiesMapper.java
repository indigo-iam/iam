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
package it.infn.mw.iam.authn.oidc.mapper;

import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.persistence.model.IamUserInfo;

@Component
public class NamedAdminAuthoritiesMapper implements OidcAuthoritiesMapper {

  private static Logger logger = LoggerFactory.getLogger(NamedAdminAuthoritiesMapper.class);

  private static final SimpleGrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");
  private static final SimpleGrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");

  private Set<SubjectIssuerGrantedAuthority> admins = new HashSet<>();

  @Override
  public Collection<? extends GrantedAuthority> mapAuthorities(JWT idToken, IamUserInfo userInfo) {

    Set<GrantedAuthority> out = new HashSet<>();
    try {
      JWTClaimsSet claims = idToken.getJWTClaimsSet();

      SubjectIssuerGrantedAuthority authority =
          new SubjectIssuerGrantedAuthority(claims.getSubject(), claims.getIssuer());
      out.add(authority);

      if (admins.contains(authority)) {
        out.add(ROLE_ADMIN);
      }

      // everybody's a user by default
      out.add(ROLE_USER);

    } catch (ParseException e) {
      logger.error("Unable to parse ID Token inside of authorities mapper (huh?)");
    }
    return out;
  }

  public Set<SubjectIssuerGrantedAuthority> getAdmins() {
    return admins;
  }

  public void setAdmins(Set<SubjectIssuerGrantedAuthority> admins) {
    this.admins = admins;
  }

}
