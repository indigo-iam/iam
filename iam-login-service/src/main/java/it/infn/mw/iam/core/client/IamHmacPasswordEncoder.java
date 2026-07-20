package it.infn.mw.iam.core.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.password.PasswordEncoder;

public class IamHmacPasswordEncoder implements PasswordEncoder {

  private final SecretKeySpec pepperKey;

  public IamHmacPasswordEncoder(String masterKey) {
    this.pepperKey = new SecretKeySpec(masterKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
  }

  @Override
  public String encode(CharSequence rawPassword) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(pepperKey);

      byte[] digest = mac.doFinal(rawPassword.toString().getBytes(StandardCharsets.UTF_8));

      return Base64.getEncoder().encodeToString(digest);

    } catch (Exception e) {
      throw new IllegalStateException("Unable to calculate HMAC", e);
    }
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {

    String calculated = encode(rawPassword);

    return MessageDigest.isEqual(calculated.getBytes(StandardCharsets.UTF_8),
        encodedPassword.getBytes(StandardCharsets.UTF_8));
  }
}
