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

import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimSchema.SchemaAttribute;

/**
 * Definition of the core SCIM Group schema
 * ({@code urn:ietf:params:scim:schemas:core:2.0:Group}).
 */
@Component
public class GroupSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {
    SchemaAttribute memberValue = attr("value", "string", false, "Member identifier", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute memberDisplay = attr("display", "string", false, "Member display name", false,
        false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute memberRef = attr("$ref", "reference", false, "Resource reference", false,
        false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("displayName", "string", false, "Group display name", true, false,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("members", "complex", true, "Group members", false, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(memberValue, memberDisplay, memberRef)));

    return new ScimSchema(ScimGroup.GROUP_SCHEMA, ScimGroup.RESOURCE_TYPE, "Group schema",
        attributes, schemaMeta(ScimGroup.GROUP_SCHEMA));
  }
}
