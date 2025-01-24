package it.infn.mw.iam.persistence.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.nimbusds.jose.EncryptionMethod;

@Converter
public class JWEEncryptionMethodStringConverter
    implements AttributeConverter<EncryptionMethod, String> {

  @Override
  public String convertToDatabaseColumn(EncryptionMethod attribute) {
    if (attribute != null) {
      return attribute.getName();
    }
    return null;
  }

  @Override
  public EncryptionMethod convertToEntityAttribute(String dbData) {
    if (dbData != null) {
      return EncryptionMethod.parse(dbData);
    }
    return null;
  }
}
