package it.infn.mw.iam.util;

import it.infn.mw.iam.core.client.IamHmacPasswordEncoder;

public class IamHmacUtil {

  private static final String MASTER_KEY = "my-super-secret-master-key-provided-by-configuration";

  public static void main(String[] args) {

    if (args.length == 0) {
      System.err.println("Please provide the secret to encode as an argument");
      System.exit(1);
    }

    IamHmacPasswordEncoder encoder = new IamHmacPasswordEncoder(MASTER_KEY);

    String encodedPwd = encoder.encode(args[0]);
    System.out.printf("Encoded secret: %s%n", encodedPwd);

    long start = System.nanoTime();
    boolean pwdMatched = encoder.matches(args[0], encodedPwd);
    double elapsed = (System.nanoTime() - start) / 1_000_000.0;

    if (pwdMatched) {
      System.out.printf("Time to match secret with HMAC-SHA256 algorithm is %.3f ms%n", elapsed);
    }
  }

}
