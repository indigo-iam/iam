package it.infn.mw.iam.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "opa")
public class OPAProperties {
    private boolean enable;
    private String host;

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public boolean isEnabled() {
        return this.enable;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getHost() {
        return this.host;
    }
}
