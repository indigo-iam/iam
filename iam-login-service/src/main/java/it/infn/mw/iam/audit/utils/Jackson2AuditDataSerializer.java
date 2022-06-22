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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.audit.AuditDataSerializer;
import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

@Component
public class Jackson2AuditDataSerializer implements AuditDataSerializer {

  public static final Logger LOG = LoggerFactory.getLogger(Jackson2AuditDataSerializer.class);
  
  final ObjectMapper mapper;
  
  @Autowired
  public Jackson2AuditDataSerializer(ObjectMapper mapper) {
    this.mapper = mapper;
  }
  
  @Override
  public String serialize(IamAuditApplicationEvent event) {
    String json;

    try {

      json = mapper.writeValueAsString(event);

    } catch (JsonProcessingException e) {
      LOG.error(e.getMessage(), e);
      json = "Data parsing error: " + e.getMessage();
    }

    return json;
   
  }
}
