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
package it.infn.mw.iam.api.scim.metadata;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;

import it.infn.mw.iam.api.scim.model.ScimMeta;
import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimSchema.SchemaAttribute;

/**
 * Base class for the SCIM schema definitions exposed by the {@code /scim/Schemas} endpoint.
 *
 * <p>
 * It holds the attribute characteristic constants defined by the SCIM specification (RFC 7643), the
 * {@link SchemaAttribute} factory and the schema {@code meta} builder, so that each concrete
 * definition only has to declare the attributes it exposes.
 */
public abstract class ScimSchemaDefinition {

  protected static final String MUTABILITY_IMMUTABLE = "immutable";
  protected static final String MUTABILITY_READ_ONLY = "readOnly";
  protected static final String MUTABILITY_READ_WRITE = "readWrite";
  protected static final String RETURNED_DEFAULT = "default";

  protected static final String UNIQUENESS_NONE = "none";
  protected static final String UNIQUENESS_SERVER = "server";
  protected static final String UNIQUENESS_GLOBAL = "global";

  private static final String SCIM_SCHEMAS_LOCATION = "/scim/Schemas";

  @Value("${iam.baseUrl}")
  private String baseUrl;

  /**
   * @return the SCIM schema described by this definition.
   */
  public abstract ScimSchema asScimSchema();

  protected SchemaAttribute attr(String name, String type, boolean multiValued, String description,
      boolean required, Boolean caseExact, String mutability, String returned, String uniqueness,
      List<String> canonicalValues, List<SchemaAttribute> subAttributes) {
    return new SchemaAttribute(name, type, multiValued, description, required, caseExact,
        mutability, returned, uniqueness, canonicalValues, subAttributes);
  }

  protected ScimMeta schemaMeta(String id) {
    return ScimMeta.builder(null, null)
      .resourceType("Schema")
      .location(baseUrl + SCIM_SCHEMAS_LOCATION + "/" + id)
      .build();
  }
}
