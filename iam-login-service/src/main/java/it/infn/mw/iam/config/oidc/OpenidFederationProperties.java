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
package it.infn.mw.iam.config.oidc;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties("openid-federation")
@Configuration
public class OpenidFederationProperties {

  private List<String> trustAnchors;

  public List<String> getTrustAnchors() {
    return trustAnchors;
  }

  public void setTrustAnchors(List<String> trustAnchors) {
    this.trustAnchors = trustAnchors;
  }

  private EntityConfigurationProperties entityConfiguration = new EntityConfigurationProperties();

  public EntityConfigurationProperties getEntityConfiguration() {
    return entityConfiguration;
  }

  public void setEntityConfiguration(EntityConfigurationProperties entityConfiguration) {
    this.entityConfiguration = entityConfiguration;
  }

  public static class EntityConfigurationProperties {

    private long expirationSeconds = 86400;

    private List<String> authorityHints;

    public long getExpirationSeconds() {
      return expirationSeconds;
    }

    public void setExpirationSeconds(long expirationSeconds) {
      this.expirationSeconds = expirationSeconds;
    }

    public List<String> getAuthorityHints() {
      return authorityHints;
    }

    public void setAuthorityHints(List<String> authorityHints) {
      this.authorityHints = authorityHints;
    }

    private FederationEntityProperties federationEntity = new FederationEntityProperties();

    public FederationEntityProperties getFederationEntity() {
      return federationEntity;
    }

    public void setFederationEntity(FederationEntityProperties federationEntity) {
      this.federationEntity = federationEntity;
    }

    public static class FederationEntityProperties {

      private String organizationName;

      private List<String> contacts;

      private String logoUri;

      public String getOrganizationName() {
        return organizationName;
      }

      public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
      }

      public List<String> getContacts() {
        return contacts;
      }

      public void setContacts(List<String> contacts) {
        this.contacts = contacts;
      }

      public String getLogoUri() {
        return logoUri;
      }

      public void setLogoUri(String logoUri) {
        this.logoUri = logoUri;
      }
    }
  }
}
