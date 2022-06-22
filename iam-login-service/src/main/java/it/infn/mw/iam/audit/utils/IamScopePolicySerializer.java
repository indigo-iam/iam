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

import static java.util.Objects.isNull;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import it.infn.mw.iam.persistence.model.IamScopePolicy;

public class IamScopePolicySerializer extends JsonSerializer<IamScopePolicy>{
  

  @Override
  public void serialize(IamScopePolicy value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException {
    
    gen.writeStartObject();
    if (isNull(value.getId())){
      gen.writeNullField("id");
    }else {
      gen.writeNumberField("id", value.getId());
    }
    
    gen.writeStringField("description", value.getDescription());
    gen.writeStringField("rule", value.getRule().name());
    gen.writeStringField("matching_policy", value.getMatchingPolicy().name());
    
    
    if (isNull(value.getAccount())) {
      gen.writeNullField("account");
    } else {
      gen.writeObjectFieldStart("account");
      gen.writeStringField("uuid", value.getAccount().getUuid());
      gen.writeStringField("name", value.getAccount().getUsername());
      gen.writeEndObject();
    }
    
    if (isNull(value.getGroup())) {
      gen.writeNullField("group");
    } else {
      gen.writeObjectFieldStart("group");
      gen.writeStringField("uuid", value.getGroup().getUuid());
      gen.writeStringField("name", value.getGroup().getName());
      gen.writeEndObject();
    }
    
    gen.writeArrayFieldStart("scopes");
    for (String s: value.getScopes()){
      gen.writeString(s);
    }
    gen.writeEndArray();
    
    gen.writeEndObject();
  }

  

}
