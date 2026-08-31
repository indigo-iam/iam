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
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimAttributeType;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimMutability;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimReturned;
import it.infn.mw.iam.api.scim.model.ScimSchema.ScimUniqueness;

/**
 * Definition of the INDIGO IAM User extension schema
 * ({@code urn:indigo-dc:scim:schemas:IndigoUser}).
 */
@Component
public class IndigoUserSchemaDefinition extends ScimSchemaDefinition {

  @Override
  public ScimSchema asScimSchema() {

    SchemaAttribute sshDisplay =
        attr("display", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "SSH key display name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute sshPrimary = attr("primary", ScimAttributeType.BOOLEAN,
        SchemaAttribute.SINGLE_VALUE, "Primary SSH key", SchemaAttribute.NOT_REQUIRED, null,
        ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute sshFingerprint =
        attr("fingerprint", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "SSH key fingerprint", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.GLOBAL, null, null);
    SchemaAttribute sshValue = attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
        "SSH public key", false, false, ScimMutability.READ_WRITE, ScimReturned.DEFAULT,
        ScimUniqueness.SERVER, null, null);
    SchemaAttribute sshCreated = attr("created", ScimAttributeType.DATE_TIME,
        SchemaAttribute.SINGLE_VALUE, "Creation timestamp", SchemaAttribute.NOT_REQUIRED, null,
        ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute sshLastModified = attr("lastModified", ScimAttributeType.DATE_TIME,
        SchemaAttribute.SINGLE_VALUE, "Last modification timestamp", SchemaAttribute.NOT_REQUIRED,
        null, ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute oidcIssuer =
        attr("issuer", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "OIDC issuer",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute oidcSubject =
        attr("subject", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "OIDC subject",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute samlIdpId =
        attr("idpId", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "SAML IdP identifier",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute samlUserId =
        attr("userId", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "SAML user identifier", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute samlAttributeId =
        attr("attributeId", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "SAML attribute identifier", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute certDisplay =
        attr("display", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Certificate display name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute certPrimary = attr("primary", ScimAttributeType.BOOLEAN,
        SchemaAttribute.SINGLE_VALUE, "Primary certificate", SchemaAttribute.NOT_REQUIRED, null,
        ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute certSubjectDn =
        attr("subjectDn", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Certificate subject DN", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute certIssuerDn =
        attr("issuerDn", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Certificate issuer DN", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute certPem =
        attr("pemEncodedCertificate", ScimAttributeType.BINARY, SchemaAttribute.SINGLE_VALUE,
            "PEM-encoded certificate", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.SERVER, null, null);
    SchemaAttribute certCreated = attr("created", ScimAttributeType.DATE_TIME,
        SchemaAttribute.SINGLE_VALUE, "Creation timestamp", SchemaAttribute.NOT_REQUIRED, null,
        ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute certLastModified = attr("lastModified", ScimAttributeType.DATE_TIME,
        SchemaAttribute.SINGLE_VALUE, "Last modification timestamp", SchemaAttribute.NOT_REQUIRED,
        null, ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute certHasProxy =
        attr("hasProxyCertificate", ScimAttributeType.BOOLEAN, SchemaAttribute.SINGLE_VALUE,
            "True when certificate has a proxy", SchemaAttribute.NOT_REQUIRED, null,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute certProxyExpiration =
        attr("proxyExpirationTime", ScimAttributeType.DATE_TIME, SchemaAttribute.SINGLE_VALUE,
            "Proxy certificate expiration time", SchemaAttribute.NOT_REQUIRED, null,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

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

    SchemaAttribute customAttributeName =
        attr("name", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Custom attribute name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute customAttributeValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Custom attribute value", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    SchemaAttribute managedGroupValue =
        attr("value", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE, "Group identifier",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute managedGroupDisplay =
        attr("display", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "Group display name", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);
    SchemaAttribute managedGroupRef =
        attr("$ref", ScimAttributeType.REFERENCE, SchemaAttribute.SINGLE_VALUE, "Group reference",
            SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null);

    List<SchemaAttribute> attributes = Arrays.asList(
        attr("serviceAccount", ScimAttributeType.BOOLEAN, SchemaAttribute.SINGLE_VALUE,
            "Service account flag", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("affiliation", ScimAttributeType.STRING, SchemaAttribute.SINGLE_VALUE,
            "User affiliation", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_WRITE, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("sshKeys", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED, "Linked SSH keys",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null,
            Arrays.asList(sshDisplay, sshPrimary, sshFingerprint, sshValue, sshCreated,
                sshLastModified)),
        attr("oidcIds", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "Linked OIDC identities", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Arrays.asList(oidcIssuer, oidcSubject)),
        attr("samlIds", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "Linked SAML identities", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Arrays.asList(samlIdpId, samlUserId, samlAttributeId)),
        attr("certificates", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "X.509 certificates", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_WRITE,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Arrays.asList(certDisplay, certPrimary, certSubjectDn, certIssuerDn, certPem,
                certCreated, certLastModified, certHasProxy, certProxyExpiration)),
        attr("aupSignatureTime", ScimAttributeType.DATE_TIME, SchemaAttribute.SINGLE_VALUE,
            "AUP signature timestamp", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("endTime", ScimAttributeType.DATE_TIME, SchemaAttribute.SINGLE_VALUE,
            "Account end time", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("labels", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED, "User labels",
            SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY, ScimReturned.DEFAULT,
            ScimUniqueness.NONE, null, Arrays.asList(labelPrefix, labelName, labelValue)),
        attr("authorities", ScimAttributeType.STRING, SchemaAttribute.MULTI_VALUED,
            "Granted authorities", SchemaAttribute.NOT_REQUIRED, SchemaAttribute.IGNORE_CASE,
            ScimMutability.READ_ONLY, ScimReturned.DEFAULT, ScimUniqueness.NONE, null, null),
        attr("attributes", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "Custom attributes", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Arrays.asList(customAttributeName, customAttributeValue)),
        attr("managedGroups", ScimAttributeType.COMPLEX, SchemaAttribute.MULTI_VALUED,
            "Managed groups", SchemaAttribute.NOT_REQUIRED, null, ScimMutability.READ_ONLY,
            ScimReturned.DEFAULT, ScimUniqueness.NONE, null,
            Arrays.asList(managedGroupValue, managedGroupDisplay, managedGroupRef)));

    return new ScimSchema(INDIGO_USER_SCHEMA, "IndigoUser", "INDIGO IAM user extension schema",
        attributes, schemaMeta(INDIGO_USER_SCHEMA));
  }
}
