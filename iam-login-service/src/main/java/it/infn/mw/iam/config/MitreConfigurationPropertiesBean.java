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

import com.google.common.collect.Lists;
import com.google.gson.Gson;

public class MitreConfigurationPropertiesBean {

  private String issuer;

  private String topbarTitle;

  private String shortTopbarTitle;

  private String logoImageUrl;

  private Long regTokenLifeTime;

  private Long rqpTokenLifeTime;

  private boolean forceHttps = false;

  private Locale locale = Locale.ENGLISH;

  private List<String> languageNamespaces = Lists.newArrayList("messages");

  private boolean dualClient = false;

  private boolean heartMode = false;

  private boolean allowCompleteDeviceCodeUri = false;

  public MitreConfigurationPropertiesBean(IamProperties properties) {

    this.issuer = properties.getIssuer().endsWith("/") ? properties.getIssuer() : properties.getIssuer() + "/";
    this.topbarTitle = properties.getTopbarTitle();
    this.logoImageUrl = properties.getLogo().getUrl();
    this.regTokenLifeTime = properties.getToken().getLifetime() <= 0L ? null : properties.getToken().getLifetime();
    this.forceHttps = false;
    this.locale = Locale.ENGLISH;
    this.allowCompleteDeviceCodeUri = properties.getDeviceCode().getAllowCompleteVerificationUri();
  }

  public String getIssuer() {
    return issuer;
  }

  public String getTopbarTitle() {
    return topbarTitle;
  }

  public String getShortTopbarTitle() {
    return shortTopbarTitle == null ? topbarTitle : shortTopbarTitle;
  }

  public String getLogoImageUrl() {
    return logoImageUrl;
  }

  public Long getRegTokenLifeTime() {
    return regTokenLifeTime;
  }

  public Long getRqpTokenLifeTime() {
    return rqpTokenLifeTime;
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
    if (isHeartMode()) {
      return false;
    }
    return dualClient;
  }

  public String getLanguageNamespacesString() {
    return new Gson().toJson(getLanguageNamespaces());
  }

  public String getDefaultLanguageNamespace() {
    return getLanguageNamespaces().get(0);
  }

  public boolean isHeartMode() {
    return heartMode;
  }

  public boolean isAllowCompleteDeviceCodeUri() {
    return allowCompleteDeviceCodeUri;
  }
}

