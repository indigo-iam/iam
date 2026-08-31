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
package it.infn.mw.iam.api.scim.model;

import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_EMPTY)
public record ScimServiceProviderConfig(Set<String> schemas, ScimCapability patch,
    ScimBulkCapability bulk, ScimFilterCapability filter, ScimCapability changePassword,
    ScimCapability sort, ScimCapability etag,
    List<ScimAuthenticationScheme> authenticationSchemes) {

  public static final String SERVICE_PROVIDER_CONFIG_SCHEMA =
      "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

  public ScimServiceProviderConfig(ScimCapability patch, ScimBulkCapability bulk,
      ScimFilterCapability filter, ScimCapability changePassword, ScimCapability sort,
      ScimCapability etag, List<ScimAuthenticationScheme> authenticationSchemes) {

    this(Set.of(SERVICE_PROVIDER_CONFIG_SCHEMA), patch, bulk, filter, changePassword,
        sort, etag, authenticationSchemes);
  }

  @JsonInclude(Include.NON_NULL)
  public record ScimCapability(boolean supported) {
  }

  @JsonInclude(Include.NON_NULL)
  public record ScimBulkCapability(boolean supported, Integer maxOperations,
      Integer maxPayloadSize) {
  }

  @JsonInclude(Include.NON_NULL)
  public record ScimFilterCapability(boolean supported, Integer maxResults) {
  }

  @JsonInclude(Include.NON_NULL)
  public record ScimAuthenticationScheme(String type, String name, String description,
      String specUri, String documentationUri, Boolean primary) {
  }
}
