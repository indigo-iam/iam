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
public class ScimSchema {

  public static final String SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema";

  private final Set<String> schemas = Collections.singleton(SCHEMA_SCHEMA);
  private final String id;
  private final String name;
  private final String description;
  private final List<SchemaAttribute> attributes;
  private final ScimMeta meta;

  public ScimSchema(String id, String name, String description, List<SchemaAttribute> attributes,
      ScimMeta meta) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.attributes = attributes;
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

  public String getDescription() {
    return description;
  }

  public List<SchemaAttribute> getAttributes() {
    return attributes;
  }

  public ScimMeta getMeta() {
    return meta;
  }

  @JsonInclude(Include.NON_NULL)
  public static class SchemaAttribute {

    private final String name;
    private final String type;
    private final boolean multiValued;
    private final String description;
    private final boolean required;
    private final Boolean caseExact;
    private final String mutability;
    private final String returned;
    private final String uniqueness;
    private final List<String> canonicalValues;
    private final List<SchemaAttribute> subAttributes;

    public SchemaAttribute(String name, String type, boolean multiValued, String description,
        boolean required, Boolean caseExact, String mutability, String returned, String uniqueness,
        List<String> canonicalValues, List<SchemaAttribute> subAttributes) {
      this.name = name;
      this.type = type;
      this.multiValued = multiValued;
      this.description = description;
      this.required = required;
      this.caseExact = caseExact;
      this.mutability = mutability;
      this.returned = returned;
      this.uniqueness = uniqueness;
      this.canonicalValues = canonicalValues;
      this.subAttributes = subAttributes;
    }

    public String getName() {
      return name;
    }

    public String getType() {
      return type;
    }

    public boolean isMultiValued() {
      return multiValued;
    }

    public String getDescription() {
      return description;
    }

    public boolean isRequired() {
      return required;
    }

    public Boolean isCaseExact() {
      return caseExact;
    }

    public String getMutability() {
      return mutability;
    }

    public String getReturned() {
      return returned;
    }

    public String getUniqueness() {
      return uniqueness;
    }

    public List<String> getCanonicalValues() {
      return canonicalValues;
    }

    public List<SchemaAttribute> getSubAttributes() {
      return subAttributes;
    }
  }
}
