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
package it.infn.mw.iam.audit.utils;

import static it.infn.mw.iam.audit.utils.JsonSerializerUtils.nullSafeWriteNumberField;
import static it.infn.mw.iam.audit.utils.JsonSerializerUtils.serializeStringArray;

import java.io.IOException;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class IamClientSerializer extends JsonSerializer<ClientDetailsEntity> {

  @Override
  public void serialize(ClientDetailsEntity value, JsonGenerator gen,
      SerializerProvider serializers) throws IOException {
    gen.writeStartObject();

    gen.writeStringField("clientId", value.getClientId());
    gen.writeStringField("clientName", value.getClientName());
    gen.writeBooleanField("dynamically_registered", value.isDynamicallyRegistered());
    gen.writeBooleanField("allow_introspection", value.isAllowIntrospection());

    serializeStringArray(gen, "redirect_uris", value.getRedirectUris());
    serializeStringArray(gen, "scope", value.getScope());
    serializeStringArray(gen, "grant_types", value.getGrantTypes());

    String authMethod = Optional.ofNullable(value.getTokenEndpointAuthMethod())
      .map(AuthMethod::getValue)
      .orElseGet(() -> "none");

    gen.writeStringField("token_endpoint_auth_method", authMethod);

    nullSafeWriteNumberField(gen, "access_token_validity_seconds",
        value.getAccessTokenValiditySeconds());

    nullSafeWriteNumberField(gen, "id_token_validity_seconds", value.getIdTokenValiditySeconds());

    nullSafeWriteNumberField(gen, "refresh_token_validity_seconds",
        value.getRefreshTokenValiditySeconds());

    nullSafeWriteNumberField(gen, "device_code_validity_seconds",
        value.getDeviceCodeValiditySeconds());

    gen.writeBooleanField("clear_access_token_on_refresh", value.isClearAccessTokensOnRefresh());

    gen.writeEndObject();
  }

}
