package it.infn.mw.iam.config.oidc;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties("openid-federation")
@Configuration
public class OpenidFederationProperties {

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
  }
}
