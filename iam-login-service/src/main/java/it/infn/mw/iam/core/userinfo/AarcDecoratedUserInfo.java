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

import java.util.Set;

import org.mitre.openid.connect.model.UserInfo;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

public class AarcDecoratedUserInfo extends DelegateUserInfoAdapter implements AarcUserInfo {

  private static final long serialVersionUID = 1L;

  public static final String EDUPERSON_SCOPED_AFFILIATION_CLAIM = "eduperson_scoped_affiliation";
  public static final String EDUPERSON_ENTITLEMENT_CLAIM = "eduperson_entitlement";
  public static final String ENTITLEMENTS_CLAIM = "entitlements";
  public static final String EDUPERSON_ASSURANCE_CLAIM = "eduperson_assurance";
  public static final String VOPERSON_ID = "voperson_id";

  private String scopedAffiliation;
  private Set<String> entitlements;
  private Set<String> assurance;
  private String vopersonId;

  public AarcDecoratedUserInfo(UserInfo delegate) {
    super(delegate);
  }

  @Override
  public JsonObject toJson() {
    JsonObject json = super.toJson();

    json.remove("groups");
    json.remove("organisation_name");

    json.add(EDUPERSON_SCOPED_AFFILIATION_CLAIM, new JsonPrimitive(getScopedAffiliation()));

    JsonArray values = new JsonArray();
    getAssurance().forEach(value -> values.add(new JsonPrimitive(value)));
    json.add(EDUPERSON_ASSURANCE_CLAIM, values);

    JsonArray urns = new JsonArray();
    getEntitlements().forEach(urn -> urns.add(new JsonPrimitive(urn)));
    json.add(ENTITLEMENTS_CLAIM, urns);
    json.add(EDUPERSON_ENTITLEMENT_CLAIM, urns);


    json.add(VOPERSON_ID, new JsonPrimitive(getVoPersonId()));

    return json;
  }

  @Override
  public String getScopedAffiliation() {
    return scopedAffiliation;
  }

  @Override
  public void setScopedAffiliation(String scopedAffiliation) {
    this.scopedAffiliation = scopedAffiliation;
  }

  @Override
  public Set<String> getEntitlements() {
    return entitlements;
  }

  @Override
  public void setEntitlements(Set<String> entitlements) {
    this.entitlements = entitlements;
  }

  @Override
  public Set<String> getAssurance() {
    return assurance;
  }

  @Override
  public void setAssurance(Set<String> assurance) {
    this.assurance = assurance;
  }

  @Override
  public void setVoPersonId(String vopersonId){
    this.vopersonId = vopersonId;
  }

  @Override
  public String getVoPersonId(){
    return this.vopersonId;
  }

  public static AarcDecoratedUserInfo forUser(UserInfo u) {
    return new AarcDecoratedUserInfo(u);
  }

}
