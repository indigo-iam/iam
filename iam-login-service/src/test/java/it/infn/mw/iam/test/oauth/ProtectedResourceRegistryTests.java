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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.ProtectedResourceProperties;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.core.web.wellknown.ProtectedResourceRegistry;

class ProtectedResourceRegistryTests {

  private static final String DATA_API = """
      protected-resources:
        - id: data-api
          resource: https://data.example.org/api
          scopes: [storage.read:/]
          bearer-methods: [header, body]
      """;

  private static final String COMPUTE_API = """
      protected-resources:
        - id: compute-api
          resource: https://compute.example.org
      """;

  @TempDir
  Path dir;

  private final CacheManager cacheManager = new ConcurrentMapCacheManager();

  private Path write(String content) throws IOException {
    return Files.writeString(dir.resolve("protected-resources.yml"), content);
  }

  private ProtectedResourceRegistry registry(Path file) {
    IamProperties properties = new IamProperties();
    properties.setBaseUrl("https://iam.example.org");
    properties.getProtectedResourcesFile().setPath(file == null ? null : file.toString());
    return new ProtectedResourceRegistry(properties, cacheManager);
  }

  private static ProtectedResourceProperties resource(String id, String uri) {
    ProtectedResourceProperties r = new ProtectedResourceProperties();
    r.setId(id);
    r.setResource(uri);
    return r;
  }

  private static String validationError(ProtectedResourceProperties... resources) {
    return assertThrows(IllegalArgumentException.class,
        () -> ProtectedResourceRegistry.validate(List.of(resources))).getMessage();
  }

  @ParameterizedTest
  @CsvSource({", https://a.example.org, id must", "a/b, https://a.example.org, id must",
      "a, , resource must", "a, /api, resource must", "a, urn:example:api, resource must",
      "a, https://a.example.org/api#x, resource must"})
  void testInvalidResourceIsRejected(String id, String uri, String error) {
    assertThat(validationError(resource(id, uri)), containsString(error));
  }

  @Test
  void testDuplicatesAndUnknownBearerMethodsAreRejected() {
    assertThat(validationError(resource("a", "https://a.example.org"),
        resource("a", "https://b.example.org")), containsString("duplicate id"));
    assertThat(validationError(resource("a", "https://a.example.org"),
        resource("b", "https://a.example.org")), containsString("duplicate resource"));

    ProtectedResourceProperties r = resource("a", "https://a.example.org");
    r.setBearerMethods(List.of("header", "cookie"));
    assertThat(validationError(r), containsString("bearer-methods"));
  }

  @Test
  void testResourcesAreLoadedFromFile() throws Exception {
    ProtectedResourceRegistry r = registry(write(DATA_API));

    ProtectedResourceProperties dataApi = r.findById("data-api").orElseThrow();
    assertThat(dataApi.getScopes(), contains("storage.read:/"));
    assertThat(dataApi.getBearerMethods(), contains("header", "body"));
    assertThat(r.resourceIdentifiers(),
        contains("https://iam.example.org", "https://data.example.org/api"));
  }

  @Test
  void testReloadReplacesResourcesAndEvictsDiscoveryCache() throws Exception {
    ProtectedResourceRegistry r = registry(write(DATA_API));
    cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).put("key", "stale");

    write(COMPUTE_API);
    r.reload();

    assertTrue(r.findById("data-api").isEmpty());
    assertThat(r.resourceIdentifiers(),
        contains("https://iam.example.org", "https://compute.example.org"));
    assertNull(cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).get("key"));
  }

  @Test
  void testFailedReloadKeepsCurrentResources() throws Exception {
    Path file = write(DATA_API);
    ProtectedResourceRegistry r = registry(file);

    write("protected-resources:\n  - id: bad/id\n    resource: https://bad.example.org\n");
    assertThrows(IllegalArgumentException.class, r::reload);
    write("protected-resources: [unclosed\n");
    assertThrows(IllegalArgumentException.class, r::reload);
    Files.delete(file);
    assertThrows(IllegalArgumentException.class, r::reload);

    assertTrue(r.findById("data-api").isPresent());
  }

  @Test
  void testReloadIfChanged() throws Exception {
    ProtectedResourceRegistry r = registry(write(DATA_API));

    write("protected-resources:\n  - id: a\n");
    r.reloadIfChanged();
    assertTrue(r.findById("data-api").isPresent());

    write(COMPUTE_API);
    r.reloadIfChanged();
    assertTrue(r.findById("compute-api").isPresent());
  }

  @Test
  void testInvalidFileAtStartupFails() throws Exception {
    Path file = write("protected-resources:\n  - id: a\n    resource: /relative\n");

    assertThrows(IllegalArgumentException.class, () -> registry(file));
  }

  @Test
  void testWithoutFileResourcesAreNotReloadable() {
    ProtectedResourceRegistry r = registry(null);

    assertTrue(r.getResources().isEmpty());
    assertThrows(IllegalStateException.class, r::reload);
  }
}
