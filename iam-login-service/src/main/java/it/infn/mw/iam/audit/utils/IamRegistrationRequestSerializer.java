package it.infn.mw.iam.audit.utils;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public class IamRegistrationRequestSerializer extends JsonSerializer<IamRegistrationRequest>{

  @Override
  public void serialize(IamRegistrationRequest value, JsonGenerator gen,
      SerializerProvider serializers) throws IOException, JsonProcessingException {
    
    gen.writeStartObject();
    gen.writeStringField("uuid", value.getUuid());
    gen.writeStringField("status", value.getStatus().name());
    gen.writeStringField("user", value.getAccount().getUsername());
    gen.writeEndObject();
    
  }

}
