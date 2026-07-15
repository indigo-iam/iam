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

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;

import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimSchema.SchemaAttribute;

/**
 * Definition of the INDIGO IAM Group extension schema
 * ({@code urn:indigo-dc:scim:schemas:IndigoGroup}).
 */
@Component
public class IndigoGroupSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {
    SchemaAttribute parentGroupValue = attr("value", "string", false,
        "Parent group identifier", false, false, MUTABILITY_IMMUTABLE, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute parentGroupDisplay = attr("display", "string", false,
        "Parent group display name", false, false, MUTABILITY_IMMUTABLE, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute parentGroupRef = attr("$ref", "reference", false, "Parent group reference",
        false, false, MUTABILITY_IMMUTABLE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    SchemaAttribute labelPrefix = attr("prefix", "string", false, "Label prefix", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute labelName = attr("name", "string", false, "Label name", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute labelValue = attr("value", "string", false, "Label value", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("parentGroup", "complex", false, "Parent group", false, null,
            MUTABILITY_IMMUTABLE, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(parentGroupValue, parentGroupDisplay, parentGroupRef)),
        attr("description", "string", false, "Group description", false, false,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("labels", "complex", true, "Group labels", false, null, MUTABILITY_READ_ONLY,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(labelPrefix, labelName, labelValue)));

    return new ScimSchema(INDIGO_GROUP_SCHEMA, "IndigoGroup",
        "INDIGO IAM group extension schema", attributes, schemaMeta(INDIGO_GROUP_SCHEMA));
  }
}
