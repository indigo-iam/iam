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
import com.fasterxml.jackson.annotation.JsonValue;

@JsonInclude(Include.NON_EMPTY)
public record ScimSchema(Set<String> schemas, String id, String name, String description,
    List<SchemaAttribute> attributes, ScimMeta meta) {

  public static final String SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema";

  public ScimSchema(String id, String name, String description, List<SchemaAttribute> attributes,
      ScimMeta meta) {

    this(Set.of(SCHEMA_SCHEMA), id, name, description, attributes, meta);
  }

  @JsonInclude(Include.NON_NULL)
  public record SchemaAttribute(String name, ScimAttributeType type, boolean multiValued, String description,
      boolean required, Boolean caseExact, ScimMutability mutability, ScimReturned returned,
      ScimUniqueness uniqueness, List<String> canonicalValues,
      List<SchemaAttribute> subAttributes) {

    public static final boolean REQUIRED = true;
    public static final boolean NOT_REQUIRED = false;

    public static final boolean MULTI_VALUED = true;
    public static final boolean SINGLE_VALUE = false;

    public static final boolean CASE_SENSITIVE = true;
    public static final boolean IGNORE_CASE = false;

  }

  public enum ScimAttributeType {

    // @formatter:off
    STRING("string"),
    BOOLEAN("boolean"),
    DECIMAL("decimal"),
    INTEGER("integer"),
    DATE_TIME("dateTime"),
    REFERENCE("reference"),
    COMPLEX("complex"),
    BINARY("binary");
    // @formatter:on

    private final String value;

    ScimAttributeType(String value) {
      this.value = value;
    }

    @JsonValue
    public String value() {
      return value;
    }
  }

  public enum ScimUniqueness {

    // @formatter:off
    NONE("none"),
    SERVER("server"),
    GLOBAL("global");
    // @formatter:on

    private final String value;

    ScimUniqueness(String value) {
      this.value = value;
    }

    @JsonValue
    public String value() {
      return value;
    }
  }

  public enum ScimReturned {

    // @formatter:off
    ALWAYS("always"),
    NEVER("never"),
    DEFAULT("default"),
    REQUEST("request");
    // @formatter:on

    private final String value;

    ScimReturned(String value) {
      this.value = value;
    }

    @JsonValue
    public String value() {
      return value;
    }
  }

  public enum ScimMutability {

    // @formatter:off
    IMMUTABLE("immutable"),
    READ_ONLY("readOnly"),
    READ_WRITE("readWrite"),
    WRITE_ONLY("writeOnly");
    // @formatter:on

    private final String value;

    ScimMutability(String value) {
      this.value = value;
    }

    @JsonValue
    public String value() {
      return value;
    }
  }
}
