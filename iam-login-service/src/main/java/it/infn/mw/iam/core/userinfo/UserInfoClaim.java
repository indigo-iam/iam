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
package it.infn.mw.iam.core.userinfo;

public enum UserInfoClaim {
  ATTR("attr"),
  SUB("sub"),
  NAME("name"),
  PREFERRED_USERNAME("preferred_username"),
  GIVEN_NAME("given_name"),
  FAMILY_NAME("family_name"),
  MIDDLE_NAME("middle_name"),
  NICKNAME("nickname"),
  PROFILE("profile"),
  PICTURE("picture"),
  WEBSITE("website"),
  GENDER("gender"),
  ZONEINFO("zoneinfo"),
  LOCALE("locale"),
  UPDATED_AT("updated_at"),
  BIRTHDATE("birthdate"),
  EMAIL("email"),
  EMAIL_VERIFIED("email_verified"),
  PHONE_NUMBER("phone_number"),
  PHONE_NUMBER_VERIFIED("phone_number_verified"),
  ADDRESS("address"),
  ORGANISATION_NAME("organisation_name"),
  GROUPS("groups"),
  WLCG_GROUPS("wlcg.groups"),
  EXTERNAL_AUTHN("external_authn"),
  EDUPERSON_SCOPED_AFFILIATION("eduperson_scoped_affiliation"),
  EDUPERSON_ENTITLEMENT("eduperson_entitlement"),
  SSH_KEYS("ssh_keys");

  private UserInfoClaim(String claimName) {
    this.claimName = claimName;
  }
  private String claimName;

  public String getClaimName() {
    return claimName;
  }
}
