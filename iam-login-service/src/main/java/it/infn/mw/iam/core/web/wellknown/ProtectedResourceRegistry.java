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
package it.infn.mw.iam.core.web.wellknown;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.ProtectedResourceProperties;

/**
 * Holds the external protected resources whose RFC 9728 metadata is hosted by IAM.
 *
 * The resources come from <code>iam.protected-resources-file.path</code> when set, otherwise from
 * <code>iam.protected-resources</code>. Only the file can be reloaded at runtime, either through
 * {@link #reload()} or, when <code>iam.protected-resources-file.check-period-secs</code> is
 * positive, whenever its content changes. A reload that fails validation keeps the current
 * resources.
 */
@Component
public class ProtectedResourceRegistry {

  public static final Logger LOG = LoggerFactory.getLogger(ProtectedResourceRegistry.class);

  private static final String FILE_ROOT_KEY = "protected-resources";
  private static final Set<String> VALID_BEARER_METHODS = Set.of("header", "body", "query");
  private static final Pattern VALID_ID = Pattern.compile("[A-Za-z0-9._-]+");

  private record Snapshot(Map<String, ProtectedResourceProperties> byId,
      List<String> resourceIdentifiers, String contentHash) {
  }

  private final IamProperties properties;
  private final CacheManager cacheManager;
  private final Optional<Path> file;
  private final AtomicReference<Snapshot> snapshot;
  private final ScheduledExecutorService fileWatcher;

  public ProtectedResourceRegistry(IamProperties properties, CacheManager cacheManager) {
    this.properties = properties;
    this.cacheManager = cacheManager;

    String path = properties.getProtectedResourcesFile().getPath();
    this.file = path == null || path.isBlank() ? Optional.empty() : Optional.of(Path.of(path));

    if (file.isPresent() && !properties.getProtectedResources().isEmpty()) {
      LOG.warn("Both iam.protected-resources and iam.protected-resources-file are set: "
          + "using {} and ignoring iam.protected-resources", file.get());
    }

    this.snapshot = new AtomicReference<>(file.map(this::loadFile)
      .orElseGet(() -> snapshot(properties.getProtectedResources(), null)));

    long checkPeriodSecs = properties.getProtectedResourcesFile().getCheckPeriodSecs();
    if (file.isPresent() && checkPeriodSecs > 0) {
      fileWatcher = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "protected-resources-file-watcher");
        t.setDaemon(true);
        return t;
      });
      fileWatcher.scheduleWithFixedDelay(this::reloadIfChanged, checkPeriodSecs, checkPeriodSecs,
          TimeUnit.SECONDS);
    } else {
      fileWatcher = null;
    }
  }

  @PreDestroy
  public void stopFileWatcher() {
    if (fileWatcher != null) {
      fileWatcher.shutdownNow();
    }
  }

  public Optional<ProtectedResourceProperties> findById(String id) {
    return Optional.ofNullable(snapshot.get().byId().get(id));
  }

  public List<ProtectedResourceProperties> getResources() {
    return List.copyOf(snapshot.get().byId().values());
  }

  /**
   * All the resource identifiers, IAM first, as published in the <code>protected_resources</code>
   * authorization server metadata parameter (RFC 9728, Section 4).
   */
  public List<String> resourceIdentifiers() {
    return snapshot.get().resourceIdentifiers();
  }

  public boolean isReloadable() {
    return file.isPresent();
  }

  /**
   * Reloads the resources from the configured file.
   *
   * @return the resources now in use
   * @throws IllegalStateException if no file is configured
   * @throws IllegalArgumentException if the file cannot be read or is not valid; the current
   *         resources are kept
   */
  public synchronized List<ProtectedResourceProperties> reload() {
    Path path = file.orElseThrow(() -> new IllegalStateException(
        "Protected resources are not reloadable: iam.protected-resources-file.path is not set"));
    replace(loadFile(path));
    return getResources();
  }

  synchronized void reloadIfChanged() {
    try {
      Path path = file.orElseThrow();
      if (!hash(Files.readAllBytes(path)).equals(snapshot.get().contentHash())) {
        replace(loadFile(path));
      }
    } catch (Exception e) {
      LOG.error("Protected resources not reloaded, keeping the current ones: {}", e.getMessage());
    }
  }

  private void replace(Snapshot newSnapshot) {
    snapshot.set(newSnapshot);
    Cache cache = cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY);
    if (cache != null) {
      cache.clear();
    }
    LOG.info("Protected resources reloaded from {}: {}", file.orElseThrow(),
        newSnapshot.byId().keySet());
  }

  private Snapshot loadFile(Path path) {
    byte[] content;
    try {
      content = Files.readAllBytes(path);
    } catch (IOException e) {
      throw new IllegalArgumentException(
          String.format("Cannot read protected resources file %s: %s", path, e.getMessage()), e);
    }

    List<ProtectedResourceProperties> resources;
    try {
      YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
      yaml.setResources(new ByteArrayResource(content));
      Properties props = yaml.getObject();
      resources = new Binder(new MapConfigurationPropertySource(props))
        .bind(FILE_ROOT_KEY, Bindable.listOf(ProtectedResourceProperties.class))
        .orElse(List.of());
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(
          String.format("Invalid protected resources file %s: %s", path, e.getMessage()), e);
    }

    return snapshot(resources, hash(content));
  }

  private Snapshot snapshot(List<ProtectedResourceProperties> resources, String contentHash) {
    Map<String, ProtectedResourceProperties> byId = validate(resources);
    List<String> identifiers = Stream
      .concat(Stream.of(ProtectedResources.iamResourceIdentifier(properties)),
          byId.values().stream().map(ProtectedResourceProperties::getResource))
      .distinct()
      .toList();
    return new Snapshot(byId, identifiers, contentHash);
  }

  private static String hash(byte[] content) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public static Map<String, ProtectedResourceProperties> validate(
      List<ProtectedResourceProperties> resources) {

    Map<String, ProtectedResourceProperties> byId = new LinkedHashMap<>();
    Set<String> identifiers = new LinkedHashSet<>();

    for (ProtectedResourceProperties r : resources) {
      String id = r.getId();
      if (id == null || !VALID_ID.matcher(id).matches()) {
        throw new IllegalArgumentException(String.format(
            "Invalid iam.protected-resources id '%s': use letters, digits, '.', '_' or '-'", id));
      }
      if (byId.containsKey(id)) {
        throw new IllegalArgumentException(
            String.format("Duplicate iam.protected-resources id '%s'", id));
      }
      validateResourceIdentifier(id, r.getResource());
      if (!identifiers.add(r.getResource())) {
        throw new IllegalArgumentException(String.format(
            "Duplicate resource '%s' in iam.protected-resources '%s'", r.getResource(), id));
      }
      if (!VALID_BEARER_METHODS.containsAll(r.getBearerMethods())) {
        throw new IllegalArgumentException(String.format(
            "Invalid bearer-methods for iam.protected-resources '%s': allowed values are %s", id,
            VALID_BEARER_METHODS));
      }
      byId.put(id, r);
    }
    return byId;
  }

  private static void validateResourceIdentifier(String id, String resource) {
    String error = null;
    if (resource == null) {
      error = "resource is required";
    } else {
      try {
        URI uri = new URI(resource);
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !"http".equalsIgnoreCase(uri.getScheme())
            || uri.getHost() == null) {
          error = "resource must be an absolute http(s) URL";
        } else if (uri.getRawFragment() != null) {
          error = "resource must not contain a fragment";
        }
      } catch (URISyntaxException e) {
        error = "resource is not a valid URL";
      }
    }
    if (error != null) {
      throw new IllegalArgumentException(
          String.format("Invalid iam.protected-resources '%s': %s", id, error));
    }
  }
}
