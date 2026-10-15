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

import static it.infn.mw.iam.api.scim.model.ScimConstants.AARC_USER_SCHEMA;

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
 * Definition of the AARC User extension schema
 * ({@code urn:geant:aarc-community:scim:schemas:core:1.0:User}).
 */
@Component
public class AarcUserSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {

    SchemaAttribute givenName =
        attr("givenName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Given name",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute familyName =
        attr("familyName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Family name",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute affiliationValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "External affiliation", SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute assuranceValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Assurance value",
            SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute entitlementValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Entitlement value",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("voPersonId", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Public subject identifier", SchemaAttribute.REQUIRED, SchemaAttribute.CASE_SENSITIVE,
            ScimMutability.IMMUTABLE, ScimReturned.DEFAULT, ScimUniqueness.SERVER, null, null),

        attr("displayName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Display name",
            SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),

        attr("name", ScimAttributeType.COMPLEX, SchemaAttribute.SINGLE_VALUE, "Person name",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(givenName, familyName)),

        attr("email", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Email address",
            SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),

        attr("organizationName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Organization name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),

        attr("schacHomeOrganization", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Organization domain", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.GLOBAL, null, null),

        attr("voPersonExternalAffiliations", ScimAttributeType.COMPLEX,
            SchemaAttribute.MULTI_VALUED, "External affiliations", SchemaAttribute.REQUIRED, null,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Collections.singletonList(affiliationValue)),

        attr("assurance", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "Assurance values", SchemaAttribute.REQUIRED, null, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Collections.singletonList(assuranceValue)),

        attr("entitlements", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "User entitlements", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Collections.singletonList(entitlementValue)));

    return new ScimSchema(AARC_USER_SCHEMA, "User", "AARC User extension schema", attributes,
        schemaMeta(AARC_USER_SCHEMA));
  }
}
