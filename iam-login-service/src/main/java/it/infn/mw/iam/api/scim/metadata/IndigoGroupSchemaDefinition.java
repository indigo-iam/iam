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
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimAttributeType;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimMutability;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimReturned;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimUniqueness;

/**
 * Definition of the INDIGO IAM Group extension schema
 * ({@code urn:indigo-dc:scim:schemas:IndigoGroup}).
 */
@Component
public class IndigoGroupSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {
    SchemaAttribute parentGroupValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Parent group identifier", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.IMMUTABLE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute parentGroupDisplay =
        attr("display", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Parent group display name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.IMMUTABLE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute parentGroupRef =
        attr("$ref", ScimAttributeType.REFERENCE, SchemaAttribute.SINGLE_VALUE,
            "Parent group reference", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.IMMUTABLE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute labelPrefix =
        attr("prefix", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Label prefix",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute labelName = attr("name", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
        "Label name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
        ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute labelValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Label value",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("parentGroup", ScimAttributeType.COMPLEX, SchemaAttribute.SINGLE_VALUE, "Parent group",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.IMMUTABLE, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null,
            Arrays.asList(parentGroupValue, parentGroupDisplay, parentGroupRef)),
        attr("description", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Group description", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("labels", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED, "Group labels",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(labelPrefix, labelName, labelValue)));

    return new ScimSchema(INDIGO_GROUP_SCHEMA, "IndigoGroup", "INDIGO IAM group extension schema",
        attributes, schemaMeta(INDIGO_GROUP_SCHEMA));
  }
}
