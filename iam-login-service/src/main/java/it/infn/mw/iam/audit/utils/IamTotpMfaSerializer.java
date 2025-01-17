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

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import it.infn.mw.iam.persistence.model.IamTotpMfa;

public class IamTotpMfaSerializer extends JsonSerializer<IamTotpMfa> {

  @Override
  public void serialize(IamTotpMfa value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException {

    gen.writeStartObject();
    gen.writeStringField("account", value.getAccount().getUsername());
    gen.writeStringField("creationTime", value.getCreationTime().toString());
    gen.writeStringField("lastUpdateTime", value.getLastUpdateTime().toString());
    gen.writeStringField("active", String.valueOf(value.isActive()));
    gen.writeEndObject();
  }

}
