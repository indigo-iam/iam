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
import static it.infn.mw.iam.api.scim.model.ScimConstants.AARC_USER_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimMeta;
import it.infn.mw.iam.api.scim.model.ScimResourceType;
import it.infn.mw.iam.api.scim.model.ScimResourceType.SchemaExtension;
import it.infn.mw.iam.api.scim.model.ScimSchema;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimAuthenticationScheme;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimBulkCapability;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimCapability;
import it.infn.mw.iam.api.scim.model.ScimServiceProviderConfig.ScimFilterCapability;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.config.scim.ScimProperties;

@Service
public class DefaultScimMetadataService implements ScimMetadataService {

  // Maximum number of results returned by a filtered query, mirroring the SCIM page size limit.
  private static final int SCIM_FILTER_MAX_RESULTS = 100;

  private static final String SCIM_RESOURCE_TYPES_LOCATION = "/scim/ResourceTypes";

  @Value("${iam.baseUrl}")
  private String baseUrl;

  private final UserSchemaDefinition userSchema;
  private final GroupSchemaDefinition groupSchema;
  private final IndigoUserSchemaDefinition indigoUserSchema;
  private final IndigoGroupSchemaDefinition indigoGroupSchema;
  private final AarcUserSchemaDefinition aarcUserSchema;
  private final AarcGroupSchemaDefinition aarcGroupSchema;
  private final ScimProperties scimProperties;

  public DefaultScimMetadataService(UserSchemaDefinition userSchema,
      GroupSchemaDefinition groupSchema, IndigoUserSchemaDefinition indigoUserSchema,
      IndigoGroupSchemaDefinition indigoGroupSchema, AarcUserSchemaDefinition aarcUserSchema,
      AarcGroupSchemaDefinition aarcGroupSchema, ScimProperties scimProperties) {
    this.userSchema = userSchema;
    this.groupSchema = groupSchema;
    this.indigoUserSchema = indigoUserSchema;
    this.indigoGroupSchema = indigoGroupSchema;
    this.aarcUserSchema = aarcUserSchema;
    this.aarcGroupSchema = aarcGroupSchema;
    this.scimProperties = scimProperties;
  }

  @Cacheable(value = "scimServiceProviderConfig", sync = true)
  @Override
  public ScimServiceProviderConfig serviceProviderConfig() {
    ScimCapability patch = new ScimCapability(true);
    ScimBulkCapability bulk = new ScimBulkCapability(true, ScimConstants.SCIM_BULK_MAX_OPERATIONS,
        ScimConstants.SCIM_BULK_MAX_PAYLOAD_SIZE);
    ScimFilterCapability filter = new ScimFilterCapability(true, SCIM_FILTER_MAX_RESULTS);
    ScimCapability changePassword = new ScimCapability(true);
    ScimCapability sort = new ScimCapability(false);
    ScimCapability etag = new ScimCapability(false);
    List<ScimAuthenticationScheme> authenticationSchemes =
        Collections.singletonList(new ScimAuthenticationScheme("oauthbearertoken",
            "OAuth Bearer Token", "Authentication scheme using OAuth 2.0 Bearer Tokens",
            "https://www.rfc-editor.org/info/rfc6750", null, true));

    return new ScimServiceProviderConfig(patch, bulk, filter, changePassword, sort, etag,
        authenticationSchemes);
  }

  @Cacheable(value = "scimResourceTypes", sync = true)
  @Override
  public List<ScimResourceType> resourceTypes() {
    return Arrays.asList(userResourceType(), groupResourceType());
  }

  @Cacheable(value = "scimSchemas", sync = true)
  @Override
  public List<ScimSchema> schemas() {
    List<ScimSchema> schemas =
        new ArrayList<>(Arrays.asList(userSchema.asScimSchema(), groupSchema.asScimSchema(),
            indigoUserSchema.asScimSchema(), indigoGroupSchema.asScimSchema()));

    if (scimProperties.isEnableAarc()) {
      schemas.add(aarcUserSchema.asScimSchema());
      schemas.add(aarcGroupSchema.asScimSchema());
    }

    return schemas;
  }

  private List<SchemaExtension> userSchemaExtensions() {
    List<SchemaExtension> extensions = new ArrayList<>();

    extensions.add(new SchemaExtension(INDIGO_USER_SCHEMA, false));

    if (scimProperties.isEnableAarc()) {
      extensions.add(new SchemaExtension(AARC_USER_SCHEMA, false));
    }

    return extensions;
  }

  private List<SchemaExtension> groupSchemaExtensions() {
    List<SchemaExtension> extensions = new ArrayList<>();

    extensions.add(new SchemaExtension(INDIGO_GROUP_SCHEMA, false));

    if (scimProperties.isEnableAarc()) {
      extensions.add(new SchemaExtension(AARC_GROUP_SCHEMA, false));
    }

    return extensions;
  }

  private ScimResourceType userResourceType() {
    return new ScimResourceType(ScimUser.RESOURCE_TYPE, ScimUser.RESOURCE_TYPE, "/Users",
        "User Account", ScimUser.USER_SCHEMA, userSchemaExtensions(),
        resourceTypeMeta(ScimUser.RESOURCE_TYPE));
  }

  private ScimResourceType groupResourceType() {
    return new ScimResourceType(ScimGroup.RESOURCE_TYPE, ScimGroup.RESOURCE_TYPE, "/Groups",
        "Group", ScimGroup.GROUP_SCHEMA, groupSchemaExtensions(),
        resourceTypeMeta(ScimGroup.RESOURCE_TYPE));
  }

  private ScimMeta resourceTypeMeta(String id) {
    return ScimMeta.builder(null, null)
      .resourceType("ResourceType")
      .location(baseUrl + SCIM_RESOURCE_TYPES_LOCATION + "/" + id)
      .build();
  }
}
