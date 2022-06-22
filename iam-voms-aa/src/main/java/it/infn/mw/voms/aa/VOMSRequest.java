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
package it.infn.mw.voms.aa;

import java.security.cert.X509Certificate;
import java.util.List;

import org.italiangrid.voms.VOMSAttribute;

import it.infn.mw.voms.api.VOMSFqan;

public interface VOMSRequest {

  public String getRequesterSubject();

  public void setRequesterSubject(String requesterSubject);

  public String getRequesterIssuer();

  public void setRequesterIssuer(String requesterIssuer);

  public String getHolderSubject();

  public void setHolderSubject(String holderSubject);

  public String getHolderIssuer();

  public void setHolderIssuer(String holderIssuer);

  public X509Certificate getHolderCert();

  public void setHolderCert(X509Certificate holderCert);

  public List<VOMSFqan> getRequestedFQANs();

  public void setRequestedFQANs(List<VOMSFqan> fqans);

  public List<VOMSAttribute> getRequestAttributes();

  public void setRequestAttributes(List<VOMSAttribute> attrs);

  public long getRequestedValidity();

  public void setRequestedValidity(long validity);

  public List<String> getTargets();

  public void setTargets(List<String> targets);

}
