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

import org.springframework.security.access.event.AuthorizationFailureEvent;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class IamAuthorizationFailureEventSerializer extends JsonSerializer<AuthorizationFailureEvent>{

  @Override
  public void serialize(AuthorizationFailureEvent value, JsonGenerator gen,
      SerializerProvider serializers) throws IOException, JsonProcessingException {
    
    gen.writeStartObject();
    gen.writeStringField("principal", value.getAuthentication().getName());
    gen.writeStringField("type", value.getAccessDeniedException().getClass().getSimpleName());
    gen.writeStringField("source", value.getSource().toString());
    gen.writeEndObject();
  }
  

}
