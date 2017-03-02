package it.infn.mw.iam.audit.utils;

import java.io.IOException;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class IamAuthenticationFailureEventSerializer 
extends JsonSerializer<AbstractAuthenticationFailureEvent>{

  @Override
  public void serialize(AbstractAuthenticationFailureEvent value, JsonGenerator gen,
      SerializerProvider serializers) throws IOException, JsonProcessingException {
    
    gen.writeStartObject();
    gen.writeStringField("message", value.getException().getMessage());
    gen.writeStringField("@type", value.getException().getClass().getSimpleName());
    gen.writeEndObject();
  }

}
