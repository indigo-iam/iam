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

import java.util.Set;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import com.nimbusds.jwt.JWTClaimNames;

import it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames;

public interface AarcExtraClaimNames extends BaseExtraClaimNames {

  String AARC_VER = "aarc_ver";

  String EDUPERSON_ASSURANCE = "eduperson_assurance";

  /**
   * @deprecated Legacy name for {@link AarcExtraClaimNames#ENTITLEMENTS}
   */
  @Deprecated(since = "1.13.0")
  String EDUPERSON_ENTITLEMENT = "eduperson_entitlement";

  String EDUPERSON_SCOPED_AFFILIATION = "eduperson_scoped_affiliation";

  String ENTITLEMENTS = "entitlements";

  String ORGANIZATION_NAME = "organization_name";

  String VOPERSON_ID = "voperson_id";

  String VOPERSON_EXTERNAL_AFFILIATION = "voperson_external_affiliation";

  public static final Set<String> ACCESS_TOKEN_REQUIRED_CLAIMS =
      Set.of(VOPERSON_ID, EDUPERSON_ASSURANCE, ENTITLEMENTS);

  public static final Set<String> ID_TOKEN_REQUIRED_CLAIMS =
      Set.of(VOPERSON_ID, EDUPERSON_ASSURANCE, ENTITLEMENTS);

  public static final Set<String> INTROSPECTION_REQUIRED_CLAIMS =
      Set.of(AARC_VER, VOPERSON_ID, EDUPERSON_ASSURANCE, ENTITLEMENTS, VOPERSON_EXTERNAL_AFFILIATION);

  public static final Set<String> USERINFO_REQUIRED_CLAIMS =
      Set.of(AARC_VER, VOPERSON_ID, EDUPERSON_ASSURANCE, ENTITLEMENTS, ORGANIZATION_NAME,
          VOPERSON_EXTERNAL_AFFILIATION, JWTClaimNames.SUBJECT, StandardClaimNames.NAME, StandardClaimNames.GIVEN_NAME,
          StandardClaimNames.FAMILY_NAME, StandardClaimNames.EMAIL);
}
