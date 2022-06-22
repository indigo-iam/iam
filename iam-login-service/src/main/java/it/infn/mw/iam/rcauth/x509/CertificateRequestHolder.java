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
package it.infn.mw.iam.rcauth.x509;

import java.io.Serializable;
import java.security.KeyPair;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CertificateRequestHolder implements Serializable{

  
  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  
  
  final KeyPair keyPair;
  
  final transient PKCS10CertificationRequest request;

  private CertificateRequestHolder(KeyPair keyPair, PKCS10CertificationRequest request) {
    this.keyPair = keyPair;
    this.request = request;
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }

  public PKCS10CertificationRequest getRequest() {
    return request;
  }

  public static CertificateRequestHolder build(KeyPair kp, PKCS10CertificationRequest req) {
    return new CertificateRequestHolder(kp, req);
  }
}
