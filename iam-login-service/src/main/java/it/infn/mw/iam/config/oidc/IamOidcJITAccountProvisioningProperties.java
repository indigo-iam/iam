package it.infn.mw.iam.config.oidc;

import java.util.Optional;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import com.google.common.base.Splitter;
import com.google.common.collect.Sets;

@Validated
@ConfigurationProperties(prefix = "oidc.jit-account-provisioning")
public class IamOidcJITAccountProvisioningProperties {

  private boolean enabled;
  private String trustedIdps = "all";
  private boolean cleanupTaskEnabled;
  private long cleanupTaskPeriodSec = 86400;
  private int inactiveAccountLifetimeDays = 15;

  // Getters e Setters
  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getTrustedIdps() {
    return trustedIdps;
  }

  public void setTrustedIdps(String trustedIdps) {
    this.trustedIdps = trustedIdps;
  }

  public Optional<Set<String>> getTrustedIdpsAsOptionalSet() {
    if ("all".equals(trustedIdps)) {
      return Optional.empty();
    }

    Set<String> trustedIdpIds =
        Sets.newHashSet(Splitter.on(",").trimResults().omitEmptyStrings().split(trustedIdps));

    if (trustedIdpIds.isEmpty()) {
      return Optional.empty();
    }

    return Optional.of(trustedIdpIds);
  }

  public boolean isCleanupTaskEnabled() {
    return cleanupTaskEnabled;
  }

  public void setCleanupTaskEnabled(boolean cleanupTaskEnabled) {
    this.cleanupTaskEnabled = cleanupTaskEnabled;
  }

  public long getCleanupTaskPeriodSec() {
    return cleanupTaskPeriodSec;
  }

  public void setCleanupTaskPeriodSec(long cleanupTaskPeriodSec) {
    this.cleanupTaskPeriodSec = cleanupTaskPeriodSec;
  }

  public int getInactiveAccountLifetimeDays() {
    return inactiveAccountLifetimeDays;
  }

  public void setInactiveAccountLifetimeDays(int inactiveAccountLifetimeDays) {
    this.inactiveAccountLifetimeDays = inactiveAccountLifetimeDays;
  }
}

