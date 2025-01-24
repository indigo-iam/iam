package it.infn.mw.iam.persistence.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Converter
public class SimpleGrantedAuthorityStringConverter
    implements AttributeConverter<SimpleGrantedAuthority, String> {

  @Override
  public String convertToDatabaseColumn(SimpleGrantedAuthority attribute) {
    if (attribute != null) {
      return attribute.getAuthority();
    }
    return null;
  }

  @Override
  public SimpleGrantedAuthority convertToEntityAttribute(String dbData) {
    if (dbData != null) {
      return new SimpleGrantedAuthority(dbData);
    }
    return null;
  }

}
