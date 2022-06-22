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

import static it.infn.mw.voms.aa.VOMSNamingScheme.isGroup;
import static it.infn.mw.voms.aa.VOMSNamingScheme.isQualifiedRole;
import static java.lang.String.format;

public class LegacyFQANEncoding implements FQANEncoding {

  private static final String NULL_CAPABILITY = "Capability=NULL";
  private static final String NULL_ROLE = "Role=NULL";

  @Override
  public String encodeFQAN(String fqan) {

    String result = null;

    if (isQualifiedRole(fqan)) {
      result = format("%s/%s", fqan, NULL_CAPABILITY);
    } else if (isGroup(fqan)) {
      result = format("%s/%s/%s", fqan, NULL_ROLE, NULL_CAPABILITY);
    }

    return result;
  }

  @Override
  public String decodeFQAN(String fqan) {

    final int index = fqan.indexOf("/" + NULL_ROLE);

    if (index > 0)
      return fqan.substring(0, index);

    final int capIndex = fqan.indexOf("/" + NULL_CAPABILITY);

    if (capIndex > 0)
      return fqan.substring(0, capIndex);

    return fqan;

  }

}
