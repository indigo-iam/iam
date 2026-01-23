package it.infn.mw.iam.core.oauth.introspection.model;

import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class TokenTypeHintConverter implements Converter<String, TokenTypeHint> {

  @Override
  public TokenTypeHint convert(String source) {

    if (source == null) {
      return null;
    }
    return TokenTypeHint.valueOf(source.toUpperCase());
  }
}
