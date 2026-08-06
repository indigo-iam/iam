package it.infn.mw.iam.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Sha256Encoder {

  public static String encode(String secret) {

    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(secret.getBytes(StandardCharsets.UTF_8));

      return Base64.getEncoder().encodeToString(digest);

    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unable to calculate SHA256", e);
    }

  }
}
