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
public record ScimResourceType(
    Set<String> schemas,
    String id,
    String name,
    String endpoint,
    String description,
    String schema,
    List<SchemaExtension> schemaExtensions,
    ScimMeta meta) {

  public static final String RESOURCE_TYPE_SCHEMA =
      "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

  public ScimResourceType(
      String id,
      String name,
      String endpoint,
      String description,
      String schema,
      List<SchemaExtension> schemaExtensions,
      ScimMeta meta) {

    this(
        Set.of(RESOURCE_TYPE_SCHEMA),
        id,
        name,
        endpoint,
        description,
        schema,
        schemaExtensions,
        meta);
  }

  @JsonInclude(Include.NON_NULL)
  public record SchemaExtension(
      String schema,
      boolean required) {
  }
}