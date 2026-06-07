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

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;

import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimSchema.SchemaAttribute;

/**
 * Definition of the INDIGO IAM User extension schema
 * ({@code urn:indigo-dc:scim:schemas:IndigoUser}).
 */
@Component
public class IndigoUserSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {

    SchemaAttribute sshDisplay = attr("display", "string", false, "SSH key display name", false,
        false, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute sshPrimary = attr("primary", "boolean", false, "Primary SSH key", false,
        null, MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_NONE, null, null);
    SchemaAttribute sshFingerprint = attr("fingerprint", "string", false,
        "SSH key fingerprint", false, false, MUTABILITY_READ_ONLY, RETURNED_DEFAULT,
        UNIQUENESS_GLOBAL, null, null);
    SchemaAttribute sshValue = attr("value", "string", false, "SSH public key", false, false,
        MUTABILITY_READ_WRITE, RETURNED_DEFAULT, UNIQUENESS_SERVER, null, null);
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
        UNIQUENESS_SERVER, null, null);
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
}
