package it.infn.mw.iam.audit.utils;

import java.io.IOException;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class IamAuthenticationSuccessSerializer extends JsonSerializer<AbstractAuthenticationEvent>{

  @Override
  public void serialize(AbstractAuthenticationEvent value, JsonGenerator gen,
      SerializerProvider serializers) throws IOException, JsonProcessingException {
    
    gen.writeStartObject();
    gen.writeStringField("principal", value.getAuthentication().getName());
    gen.writeStringField("type", value.getClass().getSimpleName());
    
    if (value.getAuthentication().getDetails() != null){
      gen.writeObjectField("details", value.getAuthentication().getDetails());
    }
    gen.writeEndObject();
  }

}
