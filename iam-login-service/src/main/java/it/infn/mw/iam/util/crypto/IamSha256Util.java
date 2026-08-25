/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.util.crypto;

import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;

public class IamSha256Util {

  public static void main(String[] args) {

    if (args.length == 0) {
      System.err.println("Please provide the secret to encode as an argument");
      System.exit(1);
    }

    IamSha256PasswordEncoder encoder = new IamSha256PasswordEncoder();

    String encodedPwd = encoder.encode(args[0]);
    System.out.printf("Encoded secret: %s%n", encodedPwd);

    long start = System.nanoTime();
    boolean pwdMatched = encoder.matches(args[0], encodedPwd);
    double elapsed = (System.nanoTime() - start) / 1_000_000.0;

    if (pwdMatched) {
      System.out.printf("Time to match secret with SHA256 algorithm is %.3f ms", elapsed);
    }
  }

}
