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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.italiangrid.voms.VOMSGenericAttribute;

import com.google.common.collect.Sets;

import it.infn.mw.voms.aa.VOMSErrorMessage;
import it.infn.mw.voms.aa.VOMSResponse;
import it.infn.mw.voms.aa.VOMSWarningMessage;

public class ResponseImpl implements VOMSResponse {

  public ResponseImpl() {

    warnings = new ArrayList<>();
    errorMessages = new ArrayList<>();
    issuedFQANs = Sets.newLinkedHashSet();
    issuedGAs = new ArrayList<>();
    targets = new ArrayList<>();
    outcome = Outcome.SUCCESS;
  }

  private Outcome outcome;
  private List<VOMSWarningMessage> warnings;
  private List<VOMSErrorMessage> errorMessages;
  private Set<String> issuedFQANs;
  private List<VOMSGenericAttribute> issuedGAs;
  private List<String> targets;
  private Date notAfter;
  private Date notBefore;

  @Override
  public Outcome getOutcome() {

    return outcome;
  }

  @Override
  public void setOutcome(Outcome o) {

    outcome = o;
  }

  @Override
  public List<VOMSWarningMessage> getWarnings() {

    return warnings;
  }

  @Override
  public List<VOMSErrorMessage> getErrorMessages() {

    return errorMessages;
  }

  @Override
  public Set<String> getIssuedFQANs() {

    return issuedFQANs;
  }

  @Override
  public void setIssuedFQANs(Set<String> issuedFQANs) {

    this.issuedFQANs = issuedFQANs;
  }

  @Override
  public List<VOMSGenericAttribute> getIssuedGAs() {

    return issuedGAs;
  }

  @Override
  public void setIssuedGAs(List<VOMSGenericAttribute> issuedGAs) {

    this.issuedGAs = issuedGAs;
  }

  @Override
  public List<String> getTargets() {

    return targets;
  }

  @Override
  public void setTargets(List<String> targets) {

    this.targets = targets;
  }

  @Override
  public Date getNotAfter() {

    return notAfter;
  }

  @Override
  public void setNotAfter(Date notAfter) {

    this.notAfter = notAfter;
  }

  @Override
  public Date getNotBefore() {

    return notBefore;
  }

  @Override
  public void setNotBefore(Date notBefore) {

    this.notBefore = notBefore;
  }

}
