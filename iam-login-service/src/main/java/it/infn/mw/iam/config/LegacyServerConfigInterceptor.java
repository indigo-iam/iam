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
package it.infn.mw.iam.config;

import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.google.gson.Gson;

@SuppressWarnings("deprecation")
@Component
public class LegacyServerConfigInterceptor extends HandlerInterceptorAdapter {

  private LegacyConfigurationProperties config;
  private LegacyUiConfiguration ui;

  public LegacyServerConfigInterceptor(IamProperties properties) {
    this.config = initConfigurationProperties(properties);
    this.ui = initUiConfiguration();
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    request.setAttribute("config", config);
    request.setAttribute("ui", ui);
    return true;
  }

  private LegacyConfigurationProperties initConfigurationProperties(IamProperties properties) {
    return new LegacyConfigurationProperties(properties.getIssuer(), properties.getTopbarTitle(),
        properties.getLogo().getUrl(),
        properties.getToken().getLifetime() <= 0L ? null : properties.getToken().getLifetime(),
        false, Locale.ENGLISH, properties.getLanguageNamespaces(), false, false,
        properties.getDeviceCode().getAllowCompleteVerificationUri());
  }

  private LegacyUiConfiguration initUiConfiguration() {
    return new LegacyUiConfiguration(
        Set.of("resources/js/client.js", "resources/js/grant.js", "resources/js/scope.js",
            "resources/js/whitelist.js", "resources/js/dynreg.js", "resources/js/rsreg.js",
            "resources/js/token.js", "resources/js/blacklist.js", "resources/js/profile.js"));
  }

  public static record LegacyConfigurationProperties(String issuer, String topbarTitle,
      String logoImageUrl, Long regTokenLifeTime, boolean forceHttps, Locale locale,
      List<String> languageNamespaces, boolean dualClient, boolean heartMode,
      boolean allowCompleteDeviceCodeUri) {

    public String getIssuer() {
      return issuer;
    }

    public String getTopbarTitle() {
      return topbarTitle;
    }

    public String getShortTopbarTitle() {
      return topbarTitle;
    }

    public String getLogoImageUrl() {
      return logoImageUrl;
    }

    public Long getRegTokenLifeTime() {
      return regTokenLifeTime;
    }

    public boolean isForceHttps() {
      return forceHttps;
    }

    public Locale getLocale() {
      return locale;
    }

    public List<String> getLanguageNamespaces() {
      return languageNamespaces;
    }

    public boolean isDualClient() {
      return !heartMode && dualClient;
    }

    public boolean isHeartMode() {
      return heartMode;
    }

    public boolean isAllowCompleteDeviceCodeUri() {
      return allowCompleteDeviceCodeUri;
    }

    public String getLanguageNamespacesString() {
      return new Gson().toJson(languageNamespaces);
    }

    public String getDefaultLanguageNamespace() {
      return languageNamespaces.get(0);
    }
  }

  public static record LegacyUiConfiguration(Set<String> jsFiles) {

    public Set<String> getJsFiles() {
      return jsFiles;
    }
  }
}
