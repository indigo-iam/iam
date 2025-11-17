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
package it.infn.mw.iam.config.saml;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import com.google.common.collect.Lists;

import it.infn.mw.iam.config.JitProvisioningProperties;

@Validated
@ConfigurationProperties(prefix = "saml.jit-account-provisioning")
public class IamSamlJITAccountProvisioningProperties extends JitProvisioningProperties {

  public enum UsernameMappingPolicy {
    randomUuidPolicy, samlIdPolicy, attributeValuePolicy;
  }

  public static class EntityAttributeMappingProperties {

    String entityIds;

    AttributeMappingProperties mapping;

    public String getEntityIds() {
      return entityIds;
    }

    public void setEntityIds(String entityIds) {
      this.entityIds = entityIds;
    }

    public AttributeMappingProperties getMapping() {
      return mapping;
    }

    public void setMapping(AttributeMappingProperties mapping) {
      this.mapping = mapping;
    }
  }


  public static class AttributeMappingProperties {

    UsernameMappingPolicy usernameMappingPolicy = UsernameMappingPolicy.samlIdPolicy;

    String emailAttribute = "mail";
    String firstNameAttribute = "givenName";
    String familyNameAttribute = "sn";
    String usernameAttribute;

    public String getEmailAttribute() {
      return emailAttribute;
    }

    public void setEmailAttribute(String emailAttribute) {
      this.emailAttribute = emailAttribute;
    }

    public String getFirstNameAttribute() {
      return firstNameAttribute;
    }

    public void setFirstNameAttribute(String firstNameAttribute) {
      this.firstNameAttribute = firstNameAttribute;
    }

    public String getFamilyNameAttribute() {
      return familyNameAttribute;
    }

    public void setFamilyNameAttribute(String familyNameAttribute) {
      this.familyNameAttribute = familyNameAttribute;
    }

    public String getUsernameAttribute() {
      return usernameAttribute;
    }

    public void setUsernameAttribute(String usernameAttribute) {
      this.usernameAttribute = usernameAttribute;
    }

    public UsernameMappingPolicy getUsernameMappingPolicy() {
      return usernameMappingPolicy;
    }

    public void setUsernameMappingPolicy(UsernameMappingPolicy usernameMappingPolicy) {
      this.usernameMappingPolicy = usernameMappingPolicy;
    }
  }

  private AttributeMappingProperties defaultMapping = new AttributeMappingProperties();

  private List<EntityAttributeMappingProperties> entityMapping = Lists.newArrayList();

  public AttributeMappingProperties getDefaultMapping() {
    return defaultMapping;
  }

  public void setDefaultMapping(AttributeMappingProperties defaultMapping) {
    this.defaultMapping = defaultMapping;
  }

  public List<EntityAttributeMappingProperties> getEntityMapping() {
    return entityMapping;
  }

  public void setEntityMapping(List<EntityAttributeMappingProperties> entityMapping) {
    this.entityMapping = entityMapping;
  }
}
