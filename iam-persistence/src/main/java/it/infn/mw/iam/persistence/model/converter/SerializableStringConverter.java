package it.infn.mw.iam.persistence.model.converter;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Converter
public class SerializableStringConverter implements AttributeConverter<Serializable, String> {

  private static Logger logger = LoggerFactory.getLogger(SerializableStringConverter.class);

  @Override
  public String convertToDatabaseColumn(Serializable attribute) {
    if (attribute == null) {
      return null;
    }
    if (attribute instanceof String) {
      return (String) attribute;
    }
    if (attribute instanceof Long) {
      return attribute.toString();
    }
    if (attribute instanceof Date) {
      return Long.toString(((Date) attribute).getTime());
    }
    logger.warn("Dropping data from request: " + attribute + " :: " + attribute.getClass());
    return null;
  }

  @Override
  public Serializable convertToEntityAttribute(String dbData) {
    return dbData;
  }

}
