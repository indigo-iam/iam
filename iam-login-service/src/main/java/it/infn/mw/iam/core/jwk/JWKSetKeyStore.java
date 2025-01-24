package it.infn.mw.iam.core.jwk;

import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.List;

import org.springframework.core.io.Resource;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

public class JWKSetKeyStore {

  private JWKSet jwkSet;

  private Resource location;

  public JWKSetKeyStore() {

  }

  public JWKSetKeyStore(JWKSet jwkSet) {
    this.jwkSet = jwkSet;
    initializeJwkSet();
  }

  private void initializeJwkSet() {

    if (jwkSet != null) {
      return;
    }
    if (location == null) {
      throw new IllegalArgumentException(
          "Key store must be initialized with at least one of a jwkSet or a location.");
    }
    if (location.exists() && location.isReadable()) {

      try {
        jwkSet = JWKSet.parse(CharStreams.toString(new InputStreamReader(location.getInputStream(), Charsets.UTF_8)));
      } catch (IOException e) {
        throw new IllegalArgumentException("Key Set resource could not be read: " + location);
      } catch (ParseException e) {
        throw new IllegalArgumentException("Key Set resource could not be parsed: " + location);
      }

    } else {
      throw new IllegalArgumentException("Key Set resource could not be read: " + location);
    }
  }

  public JWKSet getJwkSet() {
    return jwkSet;
  }

  public void setJwkSet(JWKSet jwkSet) {
    this.jwkSet = jwkSet;
    initializeJwkSet();
  }

  public Resource getLocation() {
    return location;
  }

  public void setLocation(Resource location) {
    this.location = location;
    initializeJwkSet();
  }

  public List<JWK> getKeys() {
    if (jwkSet == null) {
      initializeJwkSet();
    }
    return jwkSet.getKeys();
  }
}
