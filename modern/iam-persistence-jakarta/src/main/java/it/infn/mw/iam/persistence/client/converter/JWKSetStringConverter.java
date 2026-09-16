package it.infn.mw.iam.persistence.client.converter;

import java.text.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWKSet;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class JWKSetStringConverter implements AttributeConverter<JWKSet, String> {

  private static Logger logger = LoggerFactory.getLogger(JWKSetStringConverter.class);

  @Override
  public String convertToDatabaseColumn(JWKSet attribute) {
    return attribute != null ? attribute.toString() : null;
  }

  @Override
  public JWKSet convertToEntityAttribute(String dbData) {
    if (dbData == null) {
      return null;
    }
    try {
      return JWKSet.parse(dbData);
    } catch (ParseException e) {
      logger.error("Unable to parse JWK Set", e);
      return null;
    }
  }
}
