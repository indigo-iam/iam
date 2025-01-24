package it.infn.mw.iam.persistence.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.nimbusds.jose.JWSAlgorithm;

@Converter
public class JWSAlgorithmStringConverter implements AttributeConverter<JWSAlgorithm, String> {

  @Override
  public String convertToDatabaseColumn(JWSAlgorithm attribute) {
    if (attribute != null) {
      return attribute.getName();
    }
    return null;
  }

  @Override
  public JWSAlgorithm convertToEntityAttribute(String dbData) {
    if (dbData != null) {
      return JWSAlgorithm.parse(dbData);
    }
    return null;
  }
}
