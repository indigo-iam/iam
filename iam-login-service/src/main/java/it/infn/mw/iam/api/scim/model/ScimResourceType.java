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
public class ScimResourceType {

  public static final String RESOURCE_TYPE_SCHEMA =
      "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

  private final Set<String> schemas = Collections.singleton(RESOURCE_TYPE_SCHEMA);

  private final String id;
  private final String name;
  private final String endpoint;
  private final String description;
  private final String schema;
  private final List<SchemaExtension> schemaExtensions;
  private final ScimMeta meta;

  public ScimResourceType(String id, String name, String endpoint, String description,
      String schema, List<SchemaExtension> schemaExtensions, ScimMeta meta) {
    this.id = id;
    this.name = name;
    this.endpoint = endpoint;
    this.description = description;
    this.schema = schema;
    this.schemaExtensions = schemaExtensions;
    this.meta = meta;
  }

  public Set<String> getSchemas() {
    return schemas;
  }

  public String getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public String getDescription() {
    return description;
  }

  public String getSchema() {
    return schema;
  }

  public List<SchemaExtension> getSchemaExtensions() {
    return schemaExtensions;
  }

  public ScimMeta getMeta() {
    return meta;
  }

  @JsonInclude(Include.NON_NULL)
  public static class SchemaExtension {

    private final String schema;
    private final boolean required;

    public SchemaExtension(String schema, boolean required) {
      this.schema = schema;
      this.required = required;
    }

    public String getSchema() {
      return schema;
    }

    public boolean isRequired() {
      return required;
    }
  }
}
