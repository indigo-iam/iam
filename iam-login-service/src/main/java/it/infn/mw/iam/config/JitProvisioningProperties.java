package it.infn.mw.iam.config;

import static java.lang.Boolean.FALSE;

import java.util.Optional;
import java.util.Set;

import com.google.common.base.Splitter;
import com.google.common.collect.Sets;

public abstract class JitProvisioningProperties {

  private Boolean enabled = FALSE;
  private String trustedIdps = "all";

  public Boolean getEnabled() {
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

}
