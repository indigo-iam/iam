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
package it.infn.mw.iam.test.oauth.introspection.translation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import it.infn.mw.iam.core.oauth.introspection.translation.TranslationException;
import it.infn.mw.iam.core.oauth.introspection.translation.utility.ProtectedClaimUtils;

class ProtectedClaimUtilsTests {

  @Test
  void shouldRecognizeProtectedClaims() {
    assertTrue(ProtectedClaimUtils.isProtected("iss"));
    assertTrue(ProtectedClaimUtils.isProtected("exp"));
    assertTrue(ProtectedClaimUtils.isProtected("iat"));
    assertTrue(ProtectedClaimUtils.isProtected("nbf"));
    assertTrue(ProtectedClaimUtils.isProtected("token_type"));
    assertTrue(ProtectedClaimUtils.isProtected("client_id"));
    assertTrue(ProtectedClaimUtils.isProtected("jti"));
    assertTrue(ProtectedClaimUtils.isProtected("active"));
  }

  @Test
  void shouldNotRecognizeNormalClaimsAsProtected() {
    assertFalse(ProtectedClaimUtils.isProtected("entitlements"));
    assertFalse(ProtectedClaimUtils.isProtected("scope"));
    assertFalse(ProtectedClaimUtils.isProtected("email"));
  }

  @Test
  void shouldRejectModificationOfProtectedClaims() {
    assertThrows(TranslationException.class,
        () -> ProtectedClaimUtils.validateModifiable("active"));
  }

  @Test
  void shouldRejectNullOrBlankClaimNames() {
    assertThrows(TranslationException.class, () -> ProtectedClaimUtils.validateModifiable(null));

    assertThrows(TranslationException.class, () -> ProtectedClaimUtils.validateModifiable(" "));
  }

  @Test
  void shouldRejectAudienceTransformationForNow() {
    assertThrows(TranslationException.class,
        () -> ProtectedClaimUtils.validateSupportedForValueTransformation("aud"));
  }
}
