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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerifiedTokenFactory;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;

class MultiFactorVerifiedTokenFactoryTests {

  private static final Map<String, String> ACR_DETAILS =
      Map.of("acr", "https://refeds.org/profile/mfa");

  @Test
  void verifiedTokenGrantsTheAccountAuthoritiesAndKeepsTheLoginContext() {
    ExtendedAuthenticationToken preAuthenticated = new ExtendedAuthenticationToken("test",
        "secret", List.of(Authorities.ROLE_PRE_AUTHENTICATED));
    preAuthenticated.setAuthenticated(false);
    preAuthenticated.setPreAuthenticated(true);
    // An immutable set, as the X.509 flow builds it
    preAuthenticated
      .setAuthenticationMethodReferences(Set.of(new IamAuthenticationMethodReference("swk")));
    preAuthenticated.setFullyAuthenticatedAuthorities(
        Set.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    preAuthenticated.setDetails(ACR_DETAILS);

    ExtendedAuthenticationToken verified = (ExtendedAuthenticationToken) MultiFactorVerifiedTokenFactory
      .create(preAuthenticated, new IamAuthenticationMethodReference("hwk"));

    assertThat(verified.isAuthenticated(), is(true));
    assertThat(verified.getPrincipal(), equalTo("test"));
    assertThat(verified.getAuthorities()
      .stream()
      .map(GrantedAuthority::getAuthority)
      .collect(Collectors.toList()), containsInAnyOrder("ROLE_USER", "ROLE_ADMIN"));
    assertThat(verified.getAuthenticationMethodReferences()
      .stream()
      .map(IamAuthenticationMethodReference::getName)
      .collect(Collectors.toList()), containsInAnyOrder("swk", "hwk"));
    assertThat(verified.getDetails(), equalTo(ACR_DETAILS));
  }

  @Test
  void unsupportedAuthenticationIsRejected() {
    UsernamePasswordAuthenticationToken token =
        new UsernamePasswordAuthenticationToken("test", "secret");

    assertThrows(IllegalArgumentException.class, () -> MultiFactorVerifiedTokenFactory
      .create(token, new IamAuthenticationMethodReference("otp")));
  }
}
