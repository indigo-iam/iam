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
package it.infn.mw.iam.core.rs;

import java.text.ParseException;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import com.nimbusds.jwt.JWTParser;

public class IamAudienceAuthenticationManager implements AuthenticationManager {

  private final AuthenticationManager delegate;
  private final Set<String> acceptedAudiences;

  public IamAudienceAuthenticationManager(AuthenticationManager delegate,
      Set<String> acceptedAudiences) {
    this.delegate = delegate;
    this.acceptedAudiences = Set.copyOf(acceptedAudiences);
  }

  @Override
  public Authentication authenticate(Authentication authentication)
      throws AuthenticationException {

    Authentication result = delegate.authenticate(authentication);

    List<String> audience;
    try {
      audience = JWTParser.parse((String) authentication.getPrincipal())
        .getJWTClaimsSet()
        .getAudience();
    } catch (ParseException e) {
      throw new InvalidTokenException("Invalid access token");
    }

    // Tokens without audience are not restricted to any resource
    if (!audience.isEmpty() && audience.stream().noneMatch(acceptedAudiences::contains)) {
      throw new InvalidTokenException("The access token audience does not include this resource");
    }
    return result;
  }
}
