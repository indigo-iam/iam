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
package it.infn.mw.voms.aa.impl;

import java.security.cert.X509Certificate;
import java.util.List;

import org.italiangrid.voms.VOMSAttribute;

import it.infn.mw.voms.aa.VOMSRequest;
import it.infn.mw.voms.api.VOMSFqan;

public class RequestImpl implements VOMSRequest {

  public RequestImpl() {
    // empty ctor.
  }

  private String requesterSubject;
  private String requesterIssuer;

  private String holderSubject;
  private String holderIssuer;

  private List<VOMSFqan> requestedFQANs;
  private List<VOMSAttribute> requestAttributes;

  private List<String> targets;
  private long requestedValidity = -1L;

  private X509Certificate holderCert;

  @Override
  public List<VOMSFqan> getRequestedFQANs() {
    return requestedFQANs;
  }

  @Override
  public long getRequestedValidity() {

    return requestedValidity;
  }

  @Override
  public List<String> getTargets() {

    return targets;
  }

  @Override
  public void setRequestedFQANs(List<VOMSFqan> requestedFQANs) {

    this.requestedFQANs = requestedFQANs;
  }

  @Override
  public void setTargets(List<String> targets) {

    this.targets = targets;
  }

  @Override
  public String getRequesterSubject() {

    return requesterSubject;
  }

  @Override
  public void setRequesterSubject(String requesterSubject) {

    this.requesterSubject = requesterSubject;
  }

  @Override
  public String getRequesterIssuer() {

    return requesterIssuer;
  }

  @Override
  public void setRequesterIssuer(String requesterIssuer) {

    this.requesterIssuer = requesterIssuer;
  }

  @Override
  public String getHolderSubject() {

    return holderSubject;
  }

  @Override
  public void setHolderSubject(String holderSubject) {

    this.holderSubject = holderSubject;
  }

  @Override
  public String getHolderIssuer() {

    return holderIssuer;
  }

  @Override
  public void setHolderIssuer(String holderIssuer) {

    this.holderIssuer = holderIssuer;
  }

  @Override
  public void setRequestedValidity(long validity) {

    this.requestedValidity = validity;

  }

  @Override
  public X509Certificate getHolderCert() {

    return holderCert;
  }

  @Override
  public void setHolderCert(X509Certificate holderCert) {

    this.holderCert = holderCert;
  }

  public List<VOMSAttribute> getRequestAttributes() {
    return requestAttributes;
  }

  public void setRequestAttributes(List<VOMSAttribute> requestAttributes) {
    this.requestAttributes = requestAttributes;
  }

  @Override
  public String toString() {
    return "RequestImpl [requesterSubject=" + requesterSubject + ", requesterIssuer="
        + requesterIssuer + ", holderSubject=" + holderSubject + ", holderIssuer=" + holderIssuer
        + ", requestedFQANs=" + requestedFQANs + ", requestAttributes=" + requestAttributes
        + ", targets=" + targets + ", requestedValidity=" + requestedValidity + ", holderCert="
        + holderCert + "]";
  }
}
