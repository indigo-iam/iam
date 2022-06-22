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
import java.security.cert.X509Certificate;

import com.fasterxml.jackson.annotation.JsonIgnore;

import it.infn.mw.iam.persistence.model.IamX509Certificate;

public class IamX509AuthenticationCredential implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  private final String subject;
  private final String issuer;

  private final boolean isProxy;

  @JsonIgnore
  private final X509Certificate[] certificateChain;

  private final String certificateChainPemString;

  @JsonIgnore
  private final X509CertificateVerificationResult verificationResult;

  protected IamX509AuthenticationCredential(Builder builder) {
    this.subject = builder.subject;
    this.issuer = builder.issuer;
    this.certificateChain = builder.certificateChain;
    this.verificationResult = builder.verificationResult;
    this.certificateChainPemString = builder.certificateChainPemString;
    this.isProxy = builder.isProxy;
  }

  public static class Builder {
    private String subject;
    private String issuer;
    private X509Certificate[] certificateChain;
    private String certificateChainPemString;
    private X509CertificateVerificationResult verificationResult;
    private boolean isProxy = false;

    public Builder subject(String subject) {
      this.subject = subject;
      return this;
    }

    public Builder issuer(String issuer) {
      this.issuer = issuer;
      return this;
    }

    public Builder certificateChain(X509Certificate[] chain) {
      this.certificateChain = chain;
      return this;
    }

    public Builder verificationResult(X509CertificateVerificationResult s) {
      this.verificationResult = s;
      return this;
    }

    public Builder certificateChainPemString(String ccps) {
      this.certificateChainPemString = ccps;
      return this;
    }

    public Builder isProxy(boolean isProxy) {
      this.isProxy = isProxy;
      return this;
    }

    public IamX509AuthenticationCredential build() {
      return new IamX509AuthenticationCredential(this);
    }
  }

  public IamX509Certificate asIamX509Certificate() {
    IamX509Certificate cert = new IamX509Certificate();
    cert.setSubjectDn(getSubject());
    cert.setIssuerDn(getIssuer());
    cert.setCertificate(getCertificateChainPemString());
    return cert;
  }

  public String getSubject() {
    return subject;
  }

  public String getIssuer() {
    return issuer;
  }

  public X509Certificate[] getCertificateChain() {
    return certificateChain;
  }

  public String getCertificateChainPemString() {
    return certificateChainPemString;
  }

  public X509CertificateVerificationResult getVerificationResult() {
    return verificationResult;
  }

  public boolean failedVerification() {
    return verificationResult.failedVerification();
  }

  public String verificationError() {
    return verificationResult.error().orElse("X.509 credential is valid");
  }

  public boolean isProxy() {
    return isProxy;
  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public String toString() {
    return "IamX509AuthenticationCredential [subject=" + subject + ", issuer=" + issuer
        + ", isProxy=" + isProxy + "]";
  }
}
