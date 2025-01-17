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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;

public class ExtendedAuthenticationTokenTests {

  @Test
  void testEqualsSameObjects() {
    ExtendedAuthenticationToken token1 = new ExtendedAuthenticationToken("user1", "password");
    ExtendedAuthenticationToken token2 = token1;

    assertEquals(token1, token2, "Same objects should be equal");
  }

  @Test
  void testEqualsIdenticalFields() {
    ExtendedAuthenticationToken token1 = new ExtendedAuthenticationToken("user1", "password");
    ExtendedAuthenticationToken token2 = new ExtendedAuthenticationToken("user1", "password");

    assertEquals(token1, token2, "Objects with identical fields should be equal");
  }

  @Test
  void testEqualsDifferentFields() {
    ExtendedAuthenticationToken token1 = new ExtendedAuthenticationToken("user1", "password");
    ExtendedAuthenticationToken token2 = new ExtendedAuthenticationToken("user2", "password");

    assertNotEquals(token1, token2, "Objects with different fields should not be equal");
  }

  @Test
  void testEqualsSubclassInstance() {
    ExtendedAuthenticationToken token1 = new ExtendedAuthenticationToken("user1", "password");
    AbstractAuthenticationToken token2 = new ExtendedAuthenticationToken("user1", "password");

    assertEquals(token1, token2, "Subclass instances with identical fields should be equal");
  }

  @Test
  void testHashCodeEqualObjects() {
    ExtendedAuthenticationToken token1 = new ExtendedAuthenticationToken("user1", "password");
    ExtendedAuthenticationToken token2 = new ExtendedAuthenticationToken("user1", "password");

    assertEquals(token1.hashCode(), token2.hashCode(),
        "Equal objects must have the same hash code");
  }

  @Test
  void testHashCodeDifferentObjects() {
    ExtendedAuthenticationToken token1 = new ExtendedAuthenticationToken("user1", "password");
    ExtendedAuthenticationToken token2 = new ExtendedAuthenticationToken("user2", "password");

    assertNotEquals(token1.hashCode(), token2.hashCode(),
        "Unequal objects should not have the same hash code");
  }

  @Test
  void testEqualsWithAuthorities() {
    Set<GrantedAuthority> authorities = new HashSet<>();
    authorities.add(() -> "ROLE_USER");

    ExtendedAuthenticationToken token1 =
        new ExtendedAuthenticationToken("user1", "password", authorities);
    ExtendedAuthenticationToken token2 =
        new ExtendedAuthenticationToken("user1", "password", authorities);

    assertEquals(token1, token2, "Objects with identical authorities should be equal");
  }
}
