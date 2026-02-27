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

import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_EMPTY)
public class ScimServiceProviderConfig {

  public static final String SERVICE_PROVIDER_CONFIG_SCHEMA =
      "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

  private final Set<String> schemas = Collections.singleton(SERVICE_PROVIDER_CONFIG_SCHEMA);

  private final ScimCapability patch;
  private final ScimBulkCapability bulk;
  private final ScimFilterCapability filter;
  private final ScimCapability changePassword;
  private final ScimCapability sort;
  private final ScimCapability etag;
  private final List<ScimAuthenticationScheme> authenticationSchemes;

  public ScimServiceProviderConfig(ScimCapability patch, ScimBulkCapability bulk,
      ScimFilterCapability filter, ScimCapability changePassword, ScimCapability sort,
      ScimCapability etag, List<ScimAuthenticationScheme> authenticationSchemes) {
    this.patch = patch;
    this.bulk = bulk;
    this.filter = filter;
    this.changePassword = changePassword;
    this.sort = sort;
    this.etag = etag;
    this.authenticationSchemes = authenticationSchemes;
  }

  public Set<String> getSchemas() {
    return schemas;
  }

  public ScimCapability getPatch() {
    return patch;
  }

  public ScimBulkCapability getBulk() {
    return bulk;
  }

  public ScimFilterCapability getFilter() {
    return filter;
  }

  public ScimCapability getChangePassword() {
    return changePassword;
  }

  public ScimCapability getSort() {
    return sort;
  }

  public ScimCapability getEtag() {
    return etag;
  }

  public List<ScimAuthenticationScheme> getAuthenticationSchemes() {
    return authenticationSchemes;
  }

  @JsonInclude(Include.NON_NULL)
  public static class ScimCapability {

    private final boolean supported;

    public ScimCapability(boolean supported) {
      this.supported = supported;
    }

    public boolean isSupported() {
      return supported;
    }
  }

  @JsonInclude(Include.NON_NULL)
  public static class ScimBulkCapability extends ScimCapability {

    private final Integer maxOperations;
    private final Integer maxPayloadSize;

    public ScimBulkCapability(boolean supported, Integer maxOperations, Integer maxPayloadSize) {
      super(supported);
      this.maxOperations = maxOperations;
      this.maxPayloadSize = maxPayloadSize;
    }

    public Integer getMaxOperations() {
      return maxOperations;
    }

    public Integer getMaxPayloadSize() {
      return maxPayloadSize;
    }
  }

  @JsonInclude(Include.NON_NULL)
  public static class ScimFilterCapability extends ScimCapability {

    private final Integer maxResults;

    public ScimFilterCapability(boolean supported, Integer maxResults) {
      super(supported);
      this.maxResults = maxResults;
    }

    public Integer getMaxResults() {
      return maxResults;
    }
  }

  @JsonInclude(Include.NON_NULL)
  public static class ScimAuthenticationScheme {

    private final String type;
    private final String name;
    private final String description;
    private final String specUri;
    private final String documentationUri;
    private final Boolean primary;

    public ScimAuthenticationScheme(String type, String name, String description, String specUri,
        String documentationUri, Boolean primary) {
      this.type = type;
      this.name = name;
      this.description = description;
      this.specUri = specUri;
      this.documentationUri = documentationUri;
      this.primary = primary;
    }

    public String getType() {
      return type;
    }

    public String getName() {
      return name;
    }

    public String getDescription() {
      return description;
    }

    public String getSpecUri() {
      return specUri;
    }

    public String getDocumentationUri() {
      return documentationUri;
    }

    public Boolean isPrimary() {
      return primary;
    }
  }
}
