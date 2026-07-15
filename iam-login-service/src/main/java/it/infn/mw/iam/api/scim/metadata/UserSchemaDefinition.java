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

import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimSchema.SchemaAttribute;
import it.infn.mw.iam.api.scim.model.ScimUser;

/**
 * Definition of the core SCIM User schema
 * ({@code urn:ietf:params:scim:schemas:core:2.0:User}).
 */
@Component
public class UserSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {

    SchemaAttribute formattedName = attr("formatted", "string", false, "Formatted full name",
        false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute givenName = attr("givenName", "string", false, "Given name", true, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute familyName = attr("familyName", "string", false, "Family name", true,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute emailValue = attr("value", "string", false, "Email address", true, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_SERVER, null, null);
    SchemaAttribute emailType = attr("type", "string", false, "Email type", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE,
        Arrays.asList("work", "home", "other"), null);
    SchemaAttribute emailPrimary = attr("primary", "boolean", false, "Primary email", false,
        null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    SchemaAttribute addressType = attr("type", "string", false, "Address type", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE,
        Arrays.asList("work", "home", "other"), null);
    SchemaAttribute addressFormatted = attr("formatted", "string", false, "Formatted address",
        false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute addressStreet = attr("streetAddress", "string", false, "Street address",
        false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute addressLocality = attr("locality", "string", false, "City or locality",
        false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute addressRegion = attr("region", "string", false, "Region", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute addressPostalCode = attr("postalCode", "string", false, "Postal code",
        false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute addressCountry = attr("country", "string", false, "Country", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute addressPrimary = attr("primary", "boolean", false, "Primary address",
        false, null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    SchemaAttribute photoValue = attr("value", "string", false, "Photo URI", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute photoType = attr("type", "string", false, "Photo type", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE,
        Arrays.asList("photo", "thumbnail"), null);

    SchemaAttribute groupValue = attr("value", "string", false, "Group identifier", false,
        false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute groupDisplay = attr("display", "string", false, "Group display name",
        false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute groupRef = attr("$ref", "reference", false, "Group reference", false,
        false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("userName", "string", false, "Unique username", true, false,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_SERVER, null, null),
        attr("password", "string", false, "User password", false, false,
            MUTABILITY_WRITE_ONLY, RETURNED_NEVER, UNIQUENESS_NONE, null, null),
        attr("name", "complex", false, "User's full name", true, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(formattedName, familyName, givenName)),
        attr("displayName", "string", false, "Display name", false, false,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("nickName", "string", false, "Nickname", false, false, MUTABILITY_READ_ONLY,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("profileUrl", "string", false, "Profile URL", false, false,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("locale", "string", false, "Locale", false, false, MUTABILITY_READ_ONLY,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("timezone", "string", false, "Timezone", false, false, MUTABILITY_READ_ONLY,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("active", "boolean", false, "Active status", false, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("emails", "complex", true, "Email addresses", true, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(emailValue, emailType, emailPrimary)),
        attr("addresses", "complex", true, "Postal addresses", false, null,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(addressType, addressFormatted, addressStreet, addressLocality,
                addressRegion, addressPostalCode, addressCountry, addressPrimary)),
        attr("photos", "complex", true, "Photos", false, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, Arrays.asList(photoValue, photoType)),
        attr("groups", "complex", true, "Group memberships", false, null,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(groupValue, groupDisplay, groupRef)));

    return new ScimSchema(ScimUser.USER_SCHEMA, ScimUser.RESOURCE_TYPE, "User account schema",
        attributes, schemaMeta(ScimUser.USER_SCHEMA));
  }
}
