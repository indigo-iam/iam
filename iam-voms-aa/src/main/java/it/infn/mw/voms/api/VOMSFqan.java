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

import static java.lang.String.format;

import java.util.function.Supplier;

import javax.annotation.Generated;

import it.infn.mw.voms.aa.VOMSNamingException;
import it.infn.mw.voms.aa.VOMSNamingScheme;

public class VOMSFqan {

  private final String fqan;

  private final boolean roleFqan;

  private Supplier<VOMSNamingException> fqanParseError(String error) {
    return () -> new VOMSNamingException(error);
  }

  private VOMSFqan(String fqan) {
    roleFqan = VOMSNamingScheme.isQualifiedRole(fqan);
    this.fqan = fqan;
  }

  @Generated("eclipse")
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((fqan == null) ? 0 : fqan.hashCode());
    return result;
  }

  @Generated("eclipse")
  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    VOMSFqan other = (VOMSFqan) obj;
    if (fqan == null) {
      if (other.fqan != null)
        return false;
    } else if (!fqan.equals(other.fqan))
      return false;
    return true;
  }

  public String getFqan() {
    return fqan;
  }

  public boolean isRoleFqan() {
    return roleFqan;
  }

  public static VOMSFqan fromString(String fqan) {
    return new VOMSFqan(fqan);
  }

  public String asIamGroupName() {
    String groupName = VOMSNamingScheme.getGroupName(fqan)
      .orElseThrow(fqanParseError("Error extracting groupname from fqan"));

    if (isRoleFqan()) {
      String roleName = VOMSNamingScheme.getRoleName(fqan)
        .orElseThrow(fqanParseError("Error extracting rolename from fqan"));
      return format("%s/%s", groupName.substring(1), roleName);
    } else {
      return groupName.substring(1);
    }
  }

  @Override
  public String toString() {
    return "VOMSFqan [fqan=" + fqan + ", roleFqan=" + roleFqan + "]";
  }
}
