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

import java.io.Serializable;
import java.util.Optional;

public class X509CertificateVerificationResult implements Serializable{

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public enum Status {
    SUCCESS,
    FAILED
  }
  
  final Status verificationStatus;
  final transient Optional<String> verificationError;
  
  private X509CertificateVerificationResult(Status s, String verificationError) {
    this.verificationStatus = s;
    this.verificationError = Optional.ofNullable(verificationError);
  }

  public Status status() {
    return verificationStatus;
  }

  public Optional<String> error() {
    return verificationError;
  }
  
  public static X509CertificateVerificationResult success(){
    return new X509CertificateVerificationResult(Status.SUCCESS, null);
  }
  
  public static X509CertificateVerificationResult failed(String reason){
    return new X509CertificateVerificationResult(Status.FAILED, reason);
  }

  public boolean failedVerification(){
    return verificationStatus == Status.FAILED;
  }
  
  @Override
  public String toString() {
    return "X509CertificateVerificationResult [verificationStatus=" + verificationStatus
        + ", verificationError=" + verificationError + "]";
  }
}
