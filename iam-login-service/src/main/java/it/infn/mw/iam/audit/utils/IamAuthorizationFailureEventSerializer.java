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
