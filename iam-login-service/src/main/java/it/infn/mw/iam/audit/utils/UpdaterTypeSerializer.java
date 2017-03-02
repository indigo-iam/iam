package it.infn.mw.iam.audit.utils;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import it.infn.mw.iam.api.scim.updater.UpdaterType;

public class UpdaterTypeSerializer extends JsonSerializer<UpdaterType> {

  @Override
  public void serialize(UpdaterType value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException, JsonProcessingException {
      gen.writeString(value.getDescription());
  }

}
