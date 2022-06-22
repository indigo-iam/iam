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
package it.infn.mw.voms.api;

import javax.validation.Valid;
import javax.validation.constraints.Positive;
import javax.validation.constraints.Size;

@Valid
public class VOMSRequestDTO {
  
  @Size(max=512, message="fqans parameter length is limited to 512 characters")
  String fqans;
  
  @Positive(message="lifetime must be a positive integer")
  Long lifetime;
  
  @Size(max=512, message="targets parameter length is limited to 512 characters")
  String targets;

  public VOMSRequestDTO() {
    // empty constructor
  }

  public String getFqans() {
    return fqans;
  }

  public void setFqans(String fqans) {
    this.fqans = fqans;
  }

  public Long getLifetime() {
    return lifetime;
  }

  public void setLifetime(Long lifetime) {
    this.lifetime = lifetime;
  }

  public String getTargets() {
    return targets;
  }

  public void setTargets(String targets) {
    this.targets = targets;
  }
}
