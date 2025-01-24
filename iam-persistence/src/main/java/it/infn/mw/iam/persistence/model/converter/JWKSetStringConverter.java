package it.infn.mw.iam.persistence.model.converter;

import java.text.ParseException;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWKSet;

@Converter
public class JWKSetStringConverter implements AttributeConverter<JWKSet, String> {

  private static Logger logger = LoggerFactory.getLogger(JWKSetStringConverter.class);

  @Override
  public String convertToDatabaseColumn(JWKSet attribute) {
    if (attribute != null) {
      return attribute.toString();
    }
    return null;
  }

  @Override
  public JWKSet convertToEntityAttribute(String dbData) {
    if (dbData != null) {
      try {
        JWKSet jwks = JWKSet.parse(dbData);
        return jwks;
      } catch (ParseException e) {
        logger.error("Unable to parse JWK Set", e);
        return null;
      }
    }
    return null;
  }

}
