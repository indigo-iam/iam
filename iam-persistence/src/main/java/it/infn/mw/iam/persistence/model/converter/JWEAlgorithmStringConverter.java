package it.infn.mw.iam.persistence.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.nimbusds.jose.JWEAlgorithm;

@Converter
public class JWEAlgorithmStringConverter implements AttributeConverter<JWEAlgorithm, String> {

  @Override
  public String convertToDatabaseColumn(JWEAlgorithm attribute) {
    if (attribute != null) {
      return attribute.getName();
    }
    return null;
  }

  @Override
  public JWEAlgorithm convertToEntityAttribute(String dbData) {
    if (dbData != null) {
      return JWEAlgorithm.parse(dbData);
    }
    return null;
  }
}
