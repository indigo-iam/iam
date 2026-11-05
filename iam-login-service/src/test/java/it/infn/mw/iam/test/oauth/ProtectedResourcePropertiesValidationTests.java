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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

import it.infn.mw.iam.config.ProtectedResourceProperties;
import it.infn.mw.iam.core.web.wellknown.ProtectedResourceRegistry;

class ProtectedResourcePropertiesValidationTests {

  private static ProtectedResourceProperties resource(String id, String uri) {
    ProtectedResourceProperties r = new ProtectedResourceProperties();
    r.setId(id);
    r.setResource(uri);
    return r;
  }

  private static String startupError(ProtectedResourceProperties... resources) {
    return assertThrows(IllegalArgumentException.class,
        () -> ProtectedResourceRegistry.validate(List.of(resources))).getMessage();
  }

  @Test
  void testValidResourcesAreAccepted() {
    assertDoesNotThrow(() -> ProtectedResourceRegistry.validate(List.of(
        resource("a", "https://a.example.org/api"), resource("b.2_x-y", "http://localhost:8443"))));
  }

  @Test
  void testDuplicateResourceIsRejected() {
    assertThat(startupError(resource("a", "https://a.example.org"),
        resource("b", "https://a.example.org")), containsString("Duplicate resource"));
  }

  @Test
  void testMissingIdIsRejected() {
    assertThat(startupError(resource(null, "https://a.example.org")), containsString("id"));
  }

  @Test
  void testIdWithSlashIsRejected() {
    assertThat(startupError(resource("a/b", "https://a.example.org")), containsString("id"));
  }

  @Test
  void testDuplicateIdIsRejected() {
    assertThat(startupError(resource("a", "https://a.example.org"),
        resource("a", "https://b.example.org")), containsString("Duplicate"));
  }

  @Test
  void testMissingResourceIsRejected() {
    assertThat(startupError(resource("a", null)), containsString("required"));
  }

  @Test
  void testRelativeResourceIsRejected() {
    assertThat(startupError(resource("a", "/api")), containsString("absolute"));
  }

  @Test
  void testNonHttpResourceIsRejected() {
    assertThat(startupError(resource("a", "urn:example:api")), containsString("absolute"));
  }

  @Test
  void testResourceWithFragmentIsRejected() {
    assertThat(startupError(resource("a", "https://a.example.org/api#x")),
        containsString("fragment"));
  }

  @Test
  void testUnknownBearerMethodIsRejected() {
    ProtectedResourceProperties r = resource("a", "https://a.example.org");
    r.setBearerMethods(List.of("header", "cookie"));
    assertThat(startupError(r), containsString("bearer-methods"));
  }
}
