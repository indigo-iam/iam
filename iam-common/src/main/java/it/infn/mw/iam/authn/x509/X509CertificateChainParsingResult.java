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
package it.infn.mw.iam.authn.x509;

import java.security.cert.X509Certificate;

public class X509CertificateChainParsingResult {

  private final String pemString;
  private final X509Certificate[] chain;

  private X509CertificateChainParsingResult(String pemString, X509Certificate[] chain) {
    this.pemString = pemString;
    this.chain = chain;
  }

  public String getPemString() {
    return pemString;
  }

  public X509Certificate[] getChain() {
    return chain;
  }

  public static X509CertificateChainParsingResult from(String pemString, X509Certificate[] chain){
    return new X509CertificateChainParsingResult(pemString, chain);
  }

}
