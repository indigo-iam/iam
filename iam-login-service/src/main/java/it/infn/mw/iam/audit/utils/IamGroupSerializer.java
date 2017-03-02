package it.infn.mw.iam.audit.utils;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import it.infn.mw.iam.persistence.model.IamGroup;

public class IamGroupSerializer extends JsonSerializer<IamGroup> {

  @Override
  public void serialize(IamGroup value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException, JsonProcessingException {
      gen.writeStartObject();
      gen.writeStringField("uuid", value.getUuid());
      gen.writeStringField("name", value.getName());
      gen.writeEndObject();
  }

}
