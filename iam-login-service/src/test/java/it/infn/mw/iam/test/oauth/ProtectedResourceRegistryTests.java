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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.ProtectedResourceProperties;
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

  private ProtectedResourceRegistry registry;

  private final CacheManager cacheManager = new ConcurrentMapCacheManager();

  @AfterEach
  void stop() {
    if (registry != null) {
      registry.stopFileWatcher();
    }
  }

  private Path write(String content) throws IOException {
    return Files.writeString(dir.resolve("protected-resources.yml"), content);
  }

  private ProtectedResourceRegistry registry(Path file, long checkPeriodSecs) {
    IamProperties properties = new IamProperties();
    properties.setBaseUrl("https://iam.example.org");
    properties.getProtectedResourcesFile().setPath(file == null ? null : file.toString());
    properties.getProtectedResourcesFile().setCheckPeriodSecs(checkPeriodSecs);
    registry = new ProtectedResourceRegistry(properties, cacheManager);
    return registry;
  }

  @Test
  void testResourcesAreLoadedFromFile() throws Exception {
    ProtectedResourceRegistry r = registry(write(DATA_API), 0);

    ProtectedResourceProperties dataApi = r.findById("data-api").orElseThrow();
    assertThat(dataApi.getScopes(), contains("storage.read:/"));
    assertThat(dataApi.getBearerMethods(), contains("header", "body"));
    assertThat(r.resourceIdentifiers(),
        contains("https://iam.example.org", "https://data.example.org/api"));
    assertTrue(r.isReloadable());
  }

  @Test
  void testReloadReplacesResourcesAndEvictsDiscoveryCache() throws Exception {
    Path file = write(DATA_API);
    ProtectedResourceRegistry r = registry(file, 0);
    cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).put("key", "stale");

    write(COMPUTE_API);
    List<ProtectedResourceProperties> reloaded = r.reload();

    assertThat(reloaded.stream().map(ProtectedResourceProperties::getId).toList(),
        contains("compute-api"));
    assertTrue(r.findById("data-api").isEmpty());
    assertThat(r.resourceIdentifiers(),
        contains("https://iam.example.org", "https://compute.example.org"));
    assertNull(cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).get("key"));
  }

  @Test
  void testInvalidReloadKeepsCurrentResources() throws Exception {
    Path file = write(DATA_API);
    ProtectedResourceRegistry r = registry(file, 0);

    write("protected-resources:\n  - id: bad/id\n    resource: https://bad.example.org\n");
    String error = assertThrows(IllegalArgumentException.class, r::reload).getMessage();

    assertThat(error, containsString("bad/id"));
    assertTrue(r.findById("data-api").isPresent());
  }

  @Test
  void testMissingFileOnReloadKeepsCurrentResources() throws Exception {
    Path file = write(DATA_API);
    ProtectedResourceRegistry r = registry(file, 0);

    Files.delete(file);
    String error = assertThrows(IllegalArgumentException.class, r::reload).getMessage();

    assertThat(error, containsString("Cannot read"));
    assertTrue(r.findById("data-api").isPresent());
  }

  @Test
  void testEmptyFileMeansNoResources() throws Exception {
    ProtectedResourceRegistry r = registry(write("protected-resources: []\n"), 0);

    assertTrue(r.getResources().isEmpty());
    assertThat(r.resourceIdentifiers(), contains("https://iam.example.org"));
  }

  @Test
  void testInvalidFileAtStartupFails() throws Exception {
    Path file = write("protected-resources:\n  - id: a\n    resource: /relative\n");

    assertThrows(IllegalArgumentException.class, () -> registry(file, 0));
  }

  @Test
  void testWithoutFileResourcesAreNotReloadable() {
    ProtectedResourceRegistry r = registry(null, 0);

    assertFalse(r.isReloadable());
    assertThrows(IllegalStateException.class, r::reload);
  }

  @Test
  void testChangedFileIsReloadedPeriodically() throws Exception {
    ProtectedResourceRegistry r = registry(write(DATA_API), 1);

    write(COMPUTE_API);

    for (int i = 0; i < 100 && r.findById("compute-api").isEmpty(); i++) {
      TimeUnit.MILLISECONDS.sleep(100);
    }
    assertTrue(r.findById("compute-api").isPresent());
    assertTrue(r.findById("data-api").isEmpty());
  }

  @Test
  void testInvalidChangeIsIgnoredByPeriodicReload() throws Exception {
    ProtectedResourceRegistry r = registry(write(DATA_API), 1);

    write("protected-resources:\n  - id: a\n");
    TimeUnit.SECONDS.sleep(3);

    assertNotNull(r.findById("data-api").orElse(null));
  }
}
