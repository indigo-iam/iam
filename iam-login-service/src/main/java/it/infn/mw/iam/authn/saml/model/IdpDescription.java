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
package it.infn.mw.iam.authn.saml.model;

import java.util.List;

import org.opensaml.saml2.metadata.LocalizedString;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_EMPTY)
public class IdpDescription {

  private String entityId;
  private String organizationName;
  private String imageUrl;
  private List<LocalizedString> displayNames;

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
  }

  public String getOrganizationName() {
    return organizationName;
  }

  public void setOrganizationName(String organizationName) {
    this.organizationName = organizationName;
  }

  public String getImageUrl() {
    return imageUrl;
  }

  public void setImageUrl(String imageUrl) {
    this.imageUrl = imageUrl;
  }

  public List<LocalizedString> getDisplayNames() {
    return displayNames;
  }

  public void setDisplayNames(List<LocalizedString> displayNames) {
    this.displayNames = displayNames;
  }

  @Override
  public String toString() {
    return "IdpDescription [entityId=" + entityId + ", organizationName=" + organizationName
        + ", imageUrl=" + imageUrl + ", displayNames=" + displayNames + "]";
  }

}
