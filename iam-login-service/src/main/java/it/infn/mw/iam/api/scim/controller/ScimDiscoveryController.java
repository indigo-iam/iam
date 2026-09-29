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
package it.infn.mw.iam.api.scim.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.scim.exception.ScimForbiddenException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.metadata.ScimMetadataService;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimListResponse.ScimListResponseBuilder;
import it.infn.mw.iam.api.scim.model.ScimResourceType;
import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig;

@RestController
@RequestMapping("/scim")
public class ScimDiscoveryController {

  private static final String FILTER_NOT_SUPPORTED_MSG =
      "Filtering is not supported on this endpoint";

  private static final String RESOURCE_TYPES_ENDPOINT = "/ResourceTypes";
  private static final String SCHEMAS_ENDPOINT = "/Schemas";
  private static final String SERVICE_PROVIDER_CONFIG_ENDPOINT = "/ServiceProviderConfig";

  private final ScimMetadataService metadataService;

  public ScimDiscoveryController(ScimMetadataService metadataService) {
    this.metadataService = metadataService;
  }

  @GetMapping(value = SERVICE_PROVIDER_CONFIG_ENDPOINT, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimServiceProviderConfig serviceProviderConfig() {
    return metadataService.serviceProviderConfig();
  }

  @GetMapping(value = RESOURCE_TYPES_ENDPOINT, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimListResponse<ScimResourceType> resourceTypes(
      @RequestParam(required = false) String filter) {

    validateFilterParam(filter);
    return buildListResponse(metadataService.resourceTypes());
  }

  @GetMapping(value = RESOURCE_TYPES_ENDPOINT + "/{id}",
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimResourceType resourceType(@PathVariable String id) {
    return metadataService.resourceTypes().stream()
      .filter(resourceType -> resourceType.id().equals(id))
      .findFirst()
      .orElseThrow(() -> new ScimResourceNotFoundException(
          String.format("No ResourceType found for '%s'", id)));
  }

  @GetMapping(value = SCHEMAS_ENDPOINT, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimListResponse<ScimSchema> schemas(@RequestParam(required = false) String filter) {

    validateFilterParam(filter);
    return buildListResponse(metadataService.schemas());
  }

  @GetMapping(value = SCHEMAS_ENDPOINT + "/{id}", produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimSchema schema(@PathVariable String id) {
    return metadataService.schemas().stream()
      .filter(schema -> schema.id().equals(id))
      .findFirst()
      .orElseThrow(
          () -> new ScimResourceNotFoundException(String.format("No Schema found for '%s'", id)));
  }

  private void validateFilterParam(String filter) {
    if (filter != null) {
      throw new ScimForbiddenException(FILTER_NOT_SUPPORTED_MSG);
    }
  }

  private <T> ScimListResponse<T> buildListResponse(List<T> resources) {
    ScimListResponseBuilder<T> builder = ScimListResponse.builder();
    builder.totalResults((long) resources.size());
    builder.itemsPerPage(resources.size());
    builder.startIndex(1);
    builder.resources(resources);
    return builder.build();
  }
}
