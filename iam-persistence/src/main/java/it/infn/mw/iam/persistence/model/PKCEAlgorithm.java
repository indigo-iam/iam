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
package it.infn.mw.iam.persistence.model;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Requirement;

public final class PKCEAlgorithm extends Algorithm {

  private static final long serialVersionUID = 7752852583210088925L;

  public static final PKCEAlgorithm plain = new PKCEAlgorithm("plain", Requirement.REQUIRED);
  public static final PKCEAlgorithm S256 = new PKCEAlgorithm("S256", Requirement.OPTIONAL);

  public PKCEAlgorithm(String name, Requirement req) {
    super(name, req);
  }

  public PKCEAlgorithm(String name) {
    super(name, null);
  }

  public static PKCEAlgorithm parse(final String s) {
    if (s.equals(plain.getName())) {
      return plain;
    }
    if (s.equals(S256.getName())) {
      return S256;
    }
    return new PKCEAlgorithm(s);
  }
}
