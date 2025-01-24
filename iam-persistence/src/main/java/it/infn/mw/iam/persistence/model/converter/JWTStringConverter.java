package it.infn.mw.iam.persistence.model.converter;

import java.text.ParseException;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

@Converter
public class JWTStringConverter implements AttributeConverter<JWT, String> {

  public static Logger logger = LoggerFactory.getLogger(JWTStringConverter.class);

  @Override
  public String convertToDatabaseColumn(JWT attribute) {
    if (attribute != null) {
      return attribute.serialize();
    }
    return null;
  }

  @Override
  public JWT convertToEntityAttribute(String dbData) {
    if (dbData != null) {
      try {
        JWT jwt = JWTParser.parse(dbData);
        return jwt;
      } catch (ParseException e) {
        logger.error("Unable to parse JWT", e);
        return null;
      }
    }
    return null;
  }

}
