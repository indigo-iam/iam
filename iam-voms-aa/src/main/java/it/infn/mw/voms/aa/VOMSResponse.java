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

import java.util.Date;
import java.util.List;
import java.util.Set;

import org.italiangrid.voms.VOMSGenericAttribute;

public interface VOMSResponse {

  public enum Outcome {
    SUCCESS, FAILURE
  }

  public Outcome getOutcome();

  public void setOutcome(Outcome o);

  public List<VOMSWarningMessage> getWarnings();

  public List<VOMSErrorMessage> getErrorMessages();

  public Set<String> getIssuedFQANs();

  public void setIssuedFQANs(Set<String> issuedFQANs);

  public List<VOMSGenericAttribute> getIssuedGAs();

  public void setIssuedGAs(List<VOMSGenericAttribute> issuedGAs);

  public List<String> getTargets();

  public void setTargets(List<String> targets);

  public Date getNotAfter();

  public void setNotAfter(Date notAfter);

  public Date getNotBefore();

  public void setNotBefore(Date notBefore);
}
