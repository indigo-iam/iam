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

import it.infn.mw.iam.core.oauth.profile.iam.IamOidcScopes;

public interface AarcOidcScopes extends IamOidcScopes {

  String AARC = "aarc";

  /**
   * @deprecated
   * Legacy name for {@link AarcOidcScopes#VOPERSON_SCOPED_AFFILIATION}
   */
  @Deprecated(since="1.13.0")
  String EDUPERSON_SCOPED_AFFILIATION = AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION;

  /**
   * @deprecated
   * Legacy name for {@link AarcOidcScopes#ENTITLEMENTS}
   */
  @Deprecated(since="1.13.0")
  String EDUPERSON_ENTITLEMENT = AarcExtraClaimNames.EDUPERSON_ENTITLEMENT;

  String ENTITLEMENTS = AarcExtraClaimNames.ENTITLEMENTS;

  String EDUPERSON_ASSURANCE = AarcExtraClaimNames.EDUPERSON_ASSURANCE;

  String VOPERSON_ID = AarcExtraClaimNames.VOPERSON_ID;

  String VOPERSON_SCOPED_AFFILIATION = AarcExtraClaimNames.VOPERSON_SCOPED_AFFILIATION;

  String VOPERSON_EXTERNAL_AFFILIATION = AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION;

}
