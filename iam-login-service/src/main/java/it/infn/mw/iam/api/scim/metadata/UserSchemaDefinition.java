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
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimAttributeType;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimMutability;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimReturned;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimUniqueness;
import it.infn.mw.iam.api.scim.model.ScimUser;

/**
 * Definition of the core SCIM User schema ({@code urn:ietf:params:scim:schemas:core:2.0:User}).
 */
@Component
public class UserSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {

    SchemaAttribute formattedName =
        attr("formatted", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Formatted full name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute givenName =
        attr("givenName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Given name",
            SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute familyName =
        attr("familyName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Family name",
            SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute emailValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Email address",
            SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.SERVER, null, null);
    SchemaAttribute emailType = attr("type", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
        "Email type", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
        ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE,
        Arrays.asList("work", "home", "other"), null);
    SchemaAttribute emailPrimary = attr("primary", ScimAttributeType.BOOLEAN,
        SchemaAttribute.SINGLE_VALUE, "Primary email", SchemaAttribute.NOT_REQUIRED, null,
        ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute addressType = attr("type", ScimAttributeType.STRING,
        SchemaAttribute.SINGLE_VALUE, "Address type", SchemaAttribute.NOT_REQUIRED,
        SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY, ScimReturned.DEFAULT,
        ScimUniqueness.NONE, Arrays.asList("work", "home", "other"), null);
    SchemaAttribute addressFormatted =
        attr("formatted", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Formatted address", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute addressStreet =
        attr("streetAddress", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Street address", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute addressLocality =
        attr("locality", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "City or locality",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute addressRegion =
        attr("region", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Region",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute addressPostalCode =
        attr("postalCode", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Postal code",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute addressCountry =
        attr("country", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Country",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute addressPrimary = attr("primary", ScimAttributeType.BOOLEAN,
        SchemaAttribute.SINGLE_VALUE, "Primary address", SchemaAttribute.NOT_REQUIRED, null,
        ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute photoValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Photo URI",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute photoType =
        attr("type", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Photo type",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, Arrays.asList("photo", "thumbnail"), null);

    SchemaAttribute groupValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Group identifier",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute groupDisplay =
        attr("display", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Group display name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute groupRef =
        attr("$ref", ScimAttributeType.REFERENCE, SchemaAttribute.SINGLE_VALUE, "Group reference",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("userName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Unique username",
            SchemaAttribute.REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.SERVER, null, null),
        attr("password", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "User password",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.WRITE_ONLY,
            ScimReturned.NEVER, ScimUniqueness.NONE, null, null),
        attr("name", ScimAttributeType.COMPLEX, SchemaAttribute.SINGLE_VALUE, "User's full name",
            SchemaAttribute.REQUIRED, null, ScimMutability.READ_WRITE, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(formattedName, familyName, givenName)),
        attr("displayName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Display name",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("nickName", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Nickname",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("profileUrl", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Profile URL",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("locale", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Locale",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("timezone", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Timezone",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("active", ScimAttributeType.BOOLEAN, SchemaAttribute.SINGLE_VALUE, "Active status",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, null),
        attr("emails", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED, "Email addresses",
            SchemaAttribute.REQUIRED, null, ScimMutability.READ_WRITE, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(emailValue, emailType, emailPrimary)),
        attr("addresses", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "Postal addresses", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            List.of(addressType, addressFormatted, addressStreet, addressLocality, addressRegion,
                addressPostalCode, addressCountry, addressPrimary)),
        attr("photos", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED, "Photos",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(photoValue, photoType)),
        attr("groups", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED, "Group memberships",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(groupValue, groupDisplay, groupRef)));

    return new ScimSchema(ScimUser.USER_SCHEMA, ScimUser.RESOURCE_TYPE, "User account schema",
        attributes, schemaMeta(ScimUser.USER_SCHEMA));
  }
}
