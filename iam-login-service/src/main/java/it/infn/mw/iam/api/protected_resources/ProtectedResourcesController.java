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
package it.infn.mw.iam.api.protected_resources;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.ProtectedResourceProperties;
import it.infn.mw.iam.core.web.wellknown.ProtectedResourceMetadataEndpoint;
import it.infn.mw.iam.core.web.wellknown.ProtectedResourceRegistry;
import it.infn.mw.iam.core.web.wellknown.ProtectedResources;

/**
 * Lists the external protected resources hosted by IAM and reloads them from
 * <code>iam.protected-resources-file</code> without restarting IAM.
 *
 * A reload only affects the IAM instance serving the request; with several replicas, set
 * <code>iam.protected-resources-file.check-period-secs</code> so that each one picks up changes.
 */
@RestController
public class ProtectedResourcesController {

  public static final String ENDPOINT = "/iam/api/protected-resources";

  public record ProtectedResourceDTO(String id, String resource,
      @JsonProperty("metadata_url") String metadataUrl) {
  }

  private final ProtectedResourceRegistry registry;
  private final IamProperties properties;

  public ProtectedResourcesController(ProtectedResourceRegistry registry,
      IamProperties properties) {
    this.registry = registry;
    this.properties = properties;
  }

  @GetMapping(ENDPOINT)
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public List<ProtectedResourceDTO> listProtectedResources() {
    return toDTOs(registry.getResources());
  }

  @PostMapping(ENDPOINT + "/reload")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public List<ProtectedResourceDTO> reloadProtectedResources() {
    return toDTOs(registry.reload());
  }

  private List<ProtectedResourceDTO> toDTOs(List<ProtectedResourceProperties> resources) {
    String baseUrl = ProtectedResources.iamResourceIdentifier(properties);
    return resources.stream()
      .map(r -> new ProtectedResourceDTO(r.getId(), r.getResource(), String.format("%s/%s/%s",
          baseUrl, ProtectedResourceMetadataEndpoint.HOSTED_METADATA_URL, r.getId())))
      .toList();
  }

  @ResponseStatus(HttpStatus.CONFLICT)
  @ExceptionHandler(IllegalStateException.class)
  public String notReloadable(IllegalStateException e) {
    return e.getMessage();
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler(IllegalArgumentException.class)
  public String invalidFile(IllegalArgumentException e) {
    return e.getMessage();
  }
}
