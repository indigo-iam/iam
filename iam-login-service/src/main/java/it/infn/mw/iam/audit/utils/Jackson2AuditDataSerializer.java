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
