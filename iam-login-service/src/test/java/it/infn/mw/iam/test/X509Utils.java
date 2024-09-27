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
package it.infn.mw.iam.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

public class X509Utils {

  public static final List<X509Cert> x509Certs = new ArrayList<X509Cert>();

  static {

    IntStream.range(0, 5).forEachOrdered(n -> {
      try {
        X509Cert x509Cert = new X509Cert();
        x509Cert.display = "Personal Certificate (Test " + n + ")";
        x509Cert.certificate = new String(
            Files.readAllBytes(Paths.get("src/test/resources/x509/test" + n + ".cert.pem")));
        x509Certs.add(x509Cert);
      } catch (IOException e) {
        throw new AssertionError(e.getMessage(), e);
      }
    });
  }
}
