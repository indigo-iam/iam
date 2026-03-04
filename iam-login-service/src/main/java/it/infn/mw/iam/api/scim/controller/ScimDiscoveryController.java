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
package it.infn.mw.iam.api.scim.controller;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.scim.exception.ScimForbiddenException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimListResponse.ScimListResponseBuilder;
import it.infn.mw.iam.api.scim.model.ScimMeta;
import it.infn.mw.iam.api.scim.model.ScimResourceType;
import it.infn.mw.iam.api.scim.model.ScimResourceType.SchemaExtension;
import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimSchema.SchemaAttribute;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimAuthenticationScheme;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimBulkCapability;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimCapability;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimFilterCapability;
import it.infn.mw.iam.api.scim.model.ScimUser;

@RestController
@RequestMapping("/scim")
public class ScimDiscoveryController extends ScimControllerSupport {

  private static final String FILTER_NOT_SUPPORTED_MSG =
      "Filtering is not supported on this endpoint";

  private static final String RESOURCE_TYPES_ENDPOINT = "/ResourceTypes";
  private static final String SCHEMAS_ENDPOINT = "/Schemas";
  private static final String SERVICE_PROVIDER_CONFIG_ENDPOINT = "/ServiceProviderConfig";
  private static final String SCIM_RESOURCE_TYPES_LOCATION = "/scim/ResourceTypes";
  private static final String SCIM_SCHEMAS_LOCATION = "/scim/Schemas";

  private static final String MUTABILITY_IMMUTABLE = "immutable";
  private static final String MUTABILITY_READ_ONLY = "readOnly";
  private static final String MUTABILITY_READ_WRITE = "readWrite";
  private static final String MUTABILITY_WRITE_ONLY = "writeOnly";

  private static final String RETURNED_DEFAULT = "default";
  private static final String RETURNED_NEVER = "never";

  private static final String UNIQUENESS_NONE = "none";
  private static final String UNIQUENESS_SERVER = "server";

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @PreAuthorize("#iam.hasScope('scim:read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER')")
  @GetMapping(value = SERVICE_PROVIDER_CONFIG_ENDPOINT, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimServiceProviderConfig serviceProviderConfig() {
    ScimCapability patch = new ScimCapability(true);
    ScimBulkCapability bulk = new ScimBulkCapability(true, ScimConstants.SCIM_BULK_MAX_OPERATIONS,
        ScimConstants.SCIM_BULK_MAX_PAYLOAD_SIZE);
    ScimFilterCapability filter = new ScimFilterCapability(true, SCIM_USER_MAX_PAGE_SIZE);
    ScimCapability changePassword = new ScimCapability(true);
    ScimCapability sort = new ScimCapability(false);
    ScimCapability etag = new ScimCapability(false);
    List<ScimAuthenticationScheme> authenticationSchemes = Collections.singletonList(
        new ScimAuthenticationScheme("oauthbearertoken", "OAuth Bearer Token",
            "Authentication scheme using OAuth 2.0 Bearer Tokens",
            "https://www.rfc-editor.org/info/rfc6750", null, true));

    return new ScimServiceProviderConfig(patch, bulk, filter, changePassword, sort, etag,
        authenticationSchemes);
  }

  @PreAuthorize("#iam.hasScope('scim:read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER')")
  @GetMapping(value = RESOURCE_TYPES_ENDPOINT, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimListResponse<ScimResourceType> resourceTypes(
      @RequestParam(required = false) String filter) {

    validateFilterParam(filter);
    return buildListResponse(supportedResourceTypes());
  }

  @PreAuthorize("#iam.hasScope('scim:read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER')")
  @GetMapping(value = RESOURCE_TYPES_ENDPOINT + "/{id}",
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimResourceType resourceType(@PathVariable String id) {
    return supportedResourceTypes().stream()
      .filter(resourceType -> resourceType.getId().equals(id))
      .findFirst()
      .orElseThrow(() -> new ScimResourceNotFoundException(
          String.format("No ResourceType found for '%s'", id)));
  }

  @PreAuthorize("#iam.hasScope('scim:read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER')")
  @GetMapping(value = SCHEMAS_ENDPOINT, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimListResponse<ScimSchema> schemas(@RequestParam(required = false) String filter) {

    validateFilterParam(filter);
    return buildListResponse(supportedSchemas());
  }

  @PreAuthorize("#iam.hasScope('scim:read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER')")
  @GetMapping(value = SCHEMAS_ENDPOINT + "/{id:.+}", produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimSchema schema(@PathVariable String id) {
    return supportedSchemas().stream()
      .filter(schema -> schema.getId().equals(id))
      .findFirst()
      .orElseThrow(
          () -> new ScimResourceNotFoundException(String.format("No Schema found for '%s'", id)));
  }

  private void validateFilterParam(String filter) {
    if (filter != null) {
      throw new ScimForbiddenException(FILTER_NOT_SUPPORTED_MSG);
    }
  }

  private <T> ScimListResponse<T> buildListResponse(List<T> resources) {
    ScimListResponseBuilder<T> builder = ScimListResponse.builder();
    builder.totalResults((long) resources.size());
    builder.itemsPerPage(resources.size());
    builder.startIndex(1);
    builder.resources(resources);
    return builder.build();
  }

  private List<ScimResourceType> supportedResourceTypes() {
    return Arrays.asList(userResourceType(), groupResourceType());
  }

  private ScimResourceType userResourceType() {
    return new ScimResourceType(ScimUser.RESOURCE_TYPE, ScimUser.RESOURCE_TYPE, "/Users",
        "User Account", ScimUser.USER_SCHEMA,
        Collections.singletonList(new SchemaExtension(INDIGO_USER_SCHEMA, false)),
        resourceTypeMeta(ScimUser.RESOURCE_TYPE));
  }

  private ScimResourceType groupResourceType() {
    return new ScimResourceType(ScimGroup.RESOURCE_TYPE, ScimGroup.RESOURCE_TYPE, "/Groups",
        "Group", ScimGroup.GROUP_SCHEMA,
        Collections.singletonList(new SchemaExtension(INDIGO_GROUP_SCHEMA, false)),
        resourceTypeMeta(ScimGroup.RESOURCE_TYPE));
  }

  private List<ScimSchema> supportedSchemas() {
    return Arrays.asList(userSchema(), groupSchema(), indigoUserSchema(), indigoGroupSchema());
  }

  private ScimSchema userSchema() {

    SchemaAttribute formattedName = attr("formatted", "string", false, "Formatted full name",
        false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute givenName = attr("givenName", "string", false, "Given name", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute familyName = attr("familyName", "string", false, "Family name", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute middleName = attr("middleName", "string", false, "Middle name", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute honorificPrefix = attr("honorificPrefix", "string", false,
        "Honorific prefix", false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute honorificSuffix = attr("honorificSuffix", "string", false,
        "Honorific suffix", false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);

    SchemaAttribute emailValue = attr("value", "string", false, "Email address", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute emailType = attr("type", "string", false, "Email type", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE,
        Arrays.asList("work", "home", "other"), null);
    SchemaAttribute emailPrimary = attr("primary", "boolean", false, "Primary email", false,
        null, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    SchemaAttribute addressType = attr("type", "string", false, "Address type", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE,
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
        false, null, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    SchemaAttribute photoValue = attr("value", "string", false, "Photo URI", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute photoType = attr("type", "string", false, "Photo type", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE,
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
        attr("name", "complex", false, "User's full name", false, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(formattedName, familyName, givenName, middleName, honorificPrefix,
                honorificSuffix)),
        attr("displayName", "string", false, "Display name", false, false,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("nickName", "string", false, "Nickname", false, false, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("profileUrl", "string", false, "Profile URL", false, false,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("title", "string", false, "Title", false, false, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("userType", "string", false, "User type", false, false, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("preferredLanguage", "string", false, "Preferred language", false, false,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("locale", "string", false, "Locale", false, false, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("timezone", "string", false, "Timezone", false, false, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("active", "boolean", false, "Active status", false, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("emails", "complex", true, "Email addresses", false, null, MUTABILITY_READ_WRITE,
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

  private ScimSchema groupSchema() {
    SchemaAttribute memberValue = attr("value", "string", false, "Member identifier", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute memberDisplay = attr("display", "string", false, "Member display", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
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

  private ScimSchema indigoUserSchema() {

    SchemaAttribute sshDisplay = attr("display", "string", false, "SSH key display name", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute sshPrimary = attr("primary", "boolean", false, "Primary SSH key", false,
        null, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute sshFingerprint = attr("fingerprint", "string", false,
        "SSH key fingerprint", false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute sshValue = attr("value", "string", false, "SSH public key", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute sshCreated = attr("created", "dateTime", false, "Creation timestamp",
        false, null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute sshLastModified = attr("lastModified", "dateTime", false,
        "Last modification timestamp", false, null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);

    SchemaAttribute oidcIssuer = attr("issuer", "string", false, "OIDC issuer", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute oidcSubject = attr("subject", "string", false, "OIDC subject", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    SchemaAttribute samlIdpId = attr("idpId", "string", false, "SAML IdP identifier", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute samlUserId = attr("userId", "string", false, "SAML user identifier", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute samlAttributeId = attr("attributeId", "string", false,
        "SAML attribute identifier", false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);

    SchemaAttribute certDisplay = attr("display", "string", false, "Certificate display name",
        false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute certPrimary = attr("primary", "boolean", false, "Primary certificate",
        false, null, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute certSubjectDn = attr("subjectDn", "string", false, "Certificate subject DN",
        false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute certIssuerDn = attr("issuerDn", "string", false, "Certificate issuer DN",
        false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute certPem = attr("pemEncodedCertificate", "binary", false,
        "PEM-encoded certificate", false, false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute certCreated = attr("created", "dateTime", false, "Creation timestamp",
        false, null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute certLastModified = attr("lastModified", "dateTime", false,
        "Last modification timestamp", false, null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute certHasProxy = attr("hasProxyCertificate", "boolean", false,
        "True when certificate has a proxy", false, null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute certProxyExpiration = attr("proxyExpirationTime", "dateTime", false,
        "Proxy certificate expiration time", false, null, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);

    SchemaAttribute labelPrefix = attr("prefix", "string", false, "Label prefix", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute labelName = attr("name", "string", false, "Label name", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute labelValue = attr("value", "string", false, "Label value", false, false,
        MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    SchemaAttribute customAttributeName = attr("name", "string", false,
        "Custom attribute name", false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute customAttributeValue = attr("value", "string", false,
        "Custom attribute value", false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);

    SchemaAttribute managedGroupValue = attr("value", "string", false, "Group identifier",
        false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute managedGroupDisplay = attr("display", "string", false,
        "Group display name", false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_NONE, null, null);
    SchemaAttribute managedGroupRef = attr("$ref", "reference", false, "Group reference", false,
        false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("serviceAccount", "boolean", false, "Service account flag", false, null,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("affiliation", "string", false, "User affiliation", false, false,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("sshKeys", "complex", true, "Linked SSH keys", false, null, MUTABILITY_READ_WRITE,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(sshDisplay, sshPrimary, sshFingerprint, sshValue, sshCreated,
                sshLastModified)),
        attr("oidcIds", "complex", true, "Linked OIDC identities", false, null,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(oidcIssuer, oidcSubject)),
        attr("samlIds", "complex", true, "Linked SAML identities", false, null,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(samlIdpId, samlUserId, samlAttributeId)),
        attr("certificates", "complex", true, "X.509 certificates", false, null,
            MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(certDisplay, certPrimary, certSubjectDn, certIssuerDn, certPem,
                certCreated, certLastModified, certHasProxy, certProxyExpiration)),
        attr("aupSignatureTime", "dateTime", false, "AUP signature timestamp", false, null,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("endTime", "dateTime", false, "Account end time", false, null,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("labels", "complex", true, "User labels", false, null, MUTABILITY_READ_ONLY,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(labelPrefix, labelName, labelValue)),
        attr("authorities", "string", true, "Granted authorities", false, false,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("attributes", "complex", true, "Custom attributes", false, null,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(customAttributeName, customAttributeValue)),
        attr("managedGroups", "complex", true, "Managed groups", false, null,
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(managedGroupValue, managedGroupDisplay, managedGroupRef)));

    return new ScimSchema(INDIGO_USER_SCHEMA, "IndigoUser", "INDIGO IAM user extension schema",
        attributes, schemaMeta(INDIGO_USER_SCHEMA));
  }

  private ScimSchema indigoGroupSchema() {
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
            MUTABILITY_READ_ONLY, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null),
        attr("labels", "complex", true, "Group labels", false, null, MUTABILITY_READ_ONLY,
            RETURNED_DEFAULT, UNIQUENESS_NONE, null,
            Arrays.asList(labelPrefix, labelName, labelValue)));

    return new ScimSchema(INDIGO_GROUP_SCHEMA, "IndigoGroup",
        "INDIGO IAM group extension schema", attributes, schemaMeta(INDIGO_GROUP_SCHEMA));
  }

  private SchemaAttribute attr(String name, String type, boolean multiValued, String description,
      boolean required, Boolean caseExact, String mutability, String returned, String uniqueness,
      List<String> canonicalValues, List<SchemaAttribute> subAttributes) {
    return new SchemaAttribute(name, type, multiValued, description, required, caseExact,
        mutability, returned, uniqueness, canonicalValues, subAttributes);
  }

  private ScimMeta resourceTypeMeta(String id) {
    return ScimMeta.builder(null, null)
      .resourceType("ResourceType")
      .location(baseUrl + SCIM_RESOURCE_TYPES_LOCATION + "/" + id)
      .build();
  }

  private ScimMeta schemaMeta(String id) {
    return ScimMeta.builder(null, null)
      .resourceType("Schema")
      .location(baseUrl + SCIM_SCHEMAS_LOCATION + "/" + id)
      .build();
  }
}
