package it.infn.mw.iam.registration;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

@Component
@Primary
public class PersistentUUIDTokenGenerator implements TokenGenerator {

  private String lastToken;

  private UUIDTokenGenerator generator;

  public PersistentUUIDTokenGenerator() {
    generator = new UUIDTokenGenerator();
  }

  @Override
  public String generateToken() {

    lastToken = generator.generateToken();
    return lastToken;
  }

  public String getLastToken() {

    return lastToken;
  }

}
