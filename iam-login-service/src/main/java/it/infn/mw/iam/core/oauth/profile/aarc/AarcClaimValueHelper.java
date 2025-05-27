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
package it.infn.mw.iam.core.oauth.profile.aarc;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@Component
public class AarcClaimValueHelper implements ClaimValueHelper {

  public static final Set<String> ADDITIONAL_CLAIMS = Set.of("eduperson_scoped_affiliation",
      "eduperson_entitlement", "eduperson_assurance", "entitlements");

  @Value("${iam.aarc-profile.affiliation-scope}")
  String affiliationScope;

  @Value("${iam.aarc-profile.urn-delegated-namespace}")
  String urnDelegatedNamespace;

  @Value("${iam.aarc-profile.urn-nid}")
  String urnNid;

  @Value("${iam.aarc-profile.urn-subnamespaces}")
  String urnSubnamespaces;

  static final String DEFAULT_AFFILIATION_TYPE = "member";

  @Override
  public Object getClaimValueFromUserInfo(String claim, IamUserInfo info) {

    switch (claim) {

      case "eduperson_scoped_affiliation":
        return String.format("%s@%s", DEFAULT_AFFILIATION_TYPE, affiliationScope);

      case "eduperson_entitlement":
        return resolveGroups(info);

      case "entitlements":
        return resolveGroups(info);

      case "eduperson_assurance":
        return resolveLOA();

      case "voperson_id":
        return String.format("%s", info.getSub());

      default:
        return null;
    }
  }

  public Set<String> resolveGroups(IamUserInfo userInfo) {

    Set<String> encodedGroups = new HashSet<>();
    userInfo.getGroups().forEach(g -> encodedGroups.add(encodeGroup(g)));
    return encodedGroups;
  }

  private String encodeGroup(IamGroup group) {
    String encodedGroupName = group.getName().replaceAll("/", ":");
    String encodedSubnamespace = "";
    if (!Strings.isNullOrEmpty(urnSubnamespaces)) {
      encodedSubnamespace =
          String.format(":%s", String.join(":", urnSubnamespaces.trim().split(" ")));
    }
    return String.format("urn:%s:%s%s:group:%s", urnNid, urnDelegatedNamespace, encodedSubnamespace,
        encodedGroupName);
  }

  public Set<String> resolveLOA() {

    return Sets.newHashSet("https://refeds.org/assurance", "https://refeds.org/assurance/IAP/low");
  }

}
