package it.infn.mw.iam.util;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

public class IamPbkdf2Util {

  public static void main(String[] args) {

    if (args.length == 0) {
      System.err.println("Please provide the secret to encode as an argument");
      System.exit(1);
    }

    Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();

    String encodedPwd = encoder.encode(args[0]);
    System.out.printf("Encoded secret: %s%n", encodedPwd);

    long start = System.nanoTime();
    boolean pwdMatched = encoder.matches(args[0], encodedPwd);
    double elapsed = (System.nanoTime() - start) / 1_000_000.0;

    if (pwdMatched) {
      System.out.printf("Time to match secret with Pbkdf2 library is %.3f ms%n", elapsed);
    }
  }

}
