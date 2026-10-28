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

import static it.infn.mw.iam.api.scim.model.ScimConstants.AARC_GROUP_SCHEMA;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimSchema.SchemaAttribute;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimAttributeType;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimMutability;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimReturned;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimUniqueness;

/**
 * Definition of the AARC Group extension schema. *
 * ({@code urn:geant:aarc-community:scim:schemas:core:1.0:Group}).
 */
@Component
public class AarcGroupSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {
    SchemaAttribute memberValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Member identifier",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute memberDisplay =
        attr("display", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Member display name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute memberRef =
        attr("$ref", ScimAttributeType.REFERENCE, SchemaAttribute.SINGLE_VALUE,
            "Member resource reference", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    List<SchemaAttribute> attributes = Collections.singletonList(
        attr("members", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED, "Group members",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(memberValue, memberDisplay, memberRef)));

    return new ScimSchema(AARC_GROUP_SCHEMA, "AarcGroup", "AARC Group extension schema", attributes,
        schemaMeta(AARC_GROUP_SCHEMA));
  }
}
