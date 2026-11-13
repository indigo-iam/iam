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
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
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
import it.infn.mw.iam.config.IamProperties.ProtectedResourceProperties;

@Component
public class ProtectedResourceRegistry {

  public static final Logger LOG = LoggerFactory.getLogger(ProtectedResourceRegistry.class);

  private static final Set<String> BEARER_METHODS = Set.of("header", "body", "query");
  private static final Pattern VALID_ID = Pattern.compile("[A-Za-z0-9._-]+");

  private final String iamResourceIdentifier;
  private final CacheManager cacheManager;
  private final Path file;
  private final ScheduledExecutorService fileWatcher;

  private volatile Map<String, ProtectedResourceProperties> resources;
  private volatile byte[] fileContent;

  public ProtectedResourceRegistry(IamProperties properties, CacheManager cacheManager) {
    this.iamResourceIdentifier = properties.getBaseUrl().replaceAll("/+$", "");
    this.cacheManager = cacheManager;

    String path = properties.getProtectedResourcesFile().getPath();
    this.file = path == null || path.isBlank() ? null : Path.of(path);

    if (file == null) {
      resources = validate(properties.getProtectedResources());
    } else {
      if (!properties.getProtectedResources().isEmpty()) {
        LOG.warn("iam.protected-resources is ignored as iam.protected-resources-file is set");
      }
      load();
    }

    long period = properties.getProtectedResourcesFile().getCheckPeriodSecs();
    if (file != null && period > 0) {
      fileWatcher = Executors.newSingleThreadScheduledExecutor();
      fileWatcher.scheduleWithFixedDelay(this::reloadIfChanged, period, period, TimeUnit.SECONDS);
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

  public String iamResourceIdentifier() {
    return iamResourceIdentifier;
  }

  public String iamMetadataUrl() {
    return iamResourceIdentifier + "/" + ProtectedResourceMetadataEndpoint.PROTECTED_RESOURCE_URL;
  }

  public Optional<ProtectedResourceProperties> findById(String id) {
    return Optional.ofNullable(resources.get(id));
  }

  public List<ProtectedResourceProperties> getResources() {
    return List.copyOf(resources.values());
  }

  public List<String> resourceIdentifiers() {
    return Stream
      .concat(Stream.of(iamResourceIdentifier),
          resources.values().stream().map(ProtectedResourceProperties::getResource))
      .distinct()
      .toList();
  }

  public synchronized List<ProtectedResourceProperties> reload() {
    if (file == null) {
      throw new IllegalStateException("iam.protected-resources-file is not set");
    }
    load();
    return getResources();
  }

  public synchronized void reloadIfChanged() {
    try {
      if (!Arrays.equals(Files.readAllBytes(file), fileContent)) {
        load();
      }
    } catch (IOException | RuntimeException e) {
      LOG.error("Protected resources not reloaded: {}", e.getMessage());
    }
  }

  private void load() {
    byte[] content;
    try {
      content = Files.readAllBytes(file);
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot read " + file, e);
    }

    List<ProtectedResourceProperties> loaded;
    try {
      YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
      yaml.setResources(new ByteArrayResource(content));
      loaded = new Binder(new MapConfigurationPropertySource(yaml.getObject()))
        .bind("protected-resources", Bindable.listOf(ProtectedResourceProperties.class))
        .orElse(List.of());
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("Cannot parse " + file + ": " + e.getMessage(), e);
    }

    resources = validate(loaded);
    fileContent = content;

    // protected_resources is part of the cached discovery document
    Cache cache = cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY);
    if (cache != null) {
      cache.clear();
    }
    LOG.info("Protected resources loaded from {}: {}", file, resources.keySet());
  }

  public static Map<String, ProtectedResourceProperties> validate(
      List<ProtectedResourceProperties> resources) {

    Map<String, ProtectedResourceProperties> byId = new LinkedHashMap<>();
    for (ProtectedResourceProperties r : resources) {
      String id = r.getId();
      if (id == null || !VALID_ID.matcher(id).matches()) {
        throw invalid(id, "id must only contain letters, digits, '.', '_' or '-'");
      }
      if (byId.putIfAbsent(id, r) != null) {
        throw invalid(id, "duplicate id");
      }
      if (!isAbsoluteHttpUrlWithoutFragment(r.getResource())) {
        throw invalid(id, "resource must be an absolute http(s) URL without fragment");
      }
      if (byId.values().stream().filter(o -> o.getResource().equals(r.getResource())).count() > 1) {
        throw invalid(id, "duplicate resource " + r.getResource());
      }
      if (!BEARER_METHODS.containsAll(r.getBearerMethods())) {
        throw invalid(id, "bearer-methods must be among " + BEARER_METHODS);
      }
    }
    return byId;
  }

  private static IllegalArgumentException invalid(String id, String error) {
    return new IllegalArgumentException(
        String.format("Invalid protected resource '%s': %s", id, error));
  }

  private static boolean isAbsoluteHttpUrlWithoutFragment(String resource) {
    if (resource == null) {
      return false;
    }
    try {
      URI uri = new URI(resource);
      return ("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
          && uri.getHost() != null && uri.getRawFragment() == null;
    } catch (URISyntaxException e) {
      return false;
    }
  }
}
