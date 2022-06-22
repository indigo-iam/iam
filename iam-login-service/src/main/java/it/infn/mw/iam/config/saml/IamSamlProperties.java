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
import java.util.concurrent.TimeUnit;

import javax.validation.Valid;

import javax.validation.constraints.NotBlank;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import com.google.common.collect.Lists;

import it.infn.mw.iam.authn.common.config.ValidatorProperties;
import it.infn.mw.iam.authn.saml.profile.IamSSOProfileOptions;
import it.infn.mw.iam.config.login.LoginButtonProperties;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.AttributeMappingProperties;

@ConfigurationProperties(prefix = "saml")
@Validated
public class IamSamlProperties {
  
  @Validated
  public static class IssuerValidationProperties {
    
    @NotBlank
    String entityId;
    
    ValidatorProperties validator;

    public String getEntityId() {
      return entityId;
    }

    public void setEntityId(String entityId) {
      this.entityId = entityId;
    }

    public ValidatorProperties getValidator() {
      return validator;
    }

    public void setValidator(ValidatorProperties validator) {
      this.validator = validator;
    }
  }
  
  
  public static class RegistrationMappingProperties {
    
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
  
  public static class ProfileProperties {
    
    String entityIds;
    
    IamSSOProfileOptions options = new IamSSOProfileOptions();
    
    public String getEntityIds() {
      return entityIds;
    }

    public void setEntityIds(String entityIds) {
      this.entityIds = entityIds;
    }

    public IamSSOProfileOptions getOptions() {
      return options;
    }
    
    public void setOptions(IamSSOProfileOptions options) {
      this.options = options;
    }
  }
  
  public static class SignatureProperties {
    String algorithmName = "RSA";
    String algorithmUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
    String digestUri = SignatureConstants.ALGO_ID_DIGEST_SHA1;
    
    public String getAlgorithmName() {
      return algorithmName;
    }
    public void setAlgorithmName(String algorithmName) {
      this.algorithmName = algorithmName;
    }
    public String getAlgorithmUri() {
      return algorithmUri;
    }
    public void setAlgorithmUri(String algorithmUri) {
      this.algorithmUri = algorithmUri;
    }
    public String getDigestUri() {
      return digestUri;
    }
    public void setDigestUri(String digestUri) {
      this.digestUri = digestUri;
    }
  }

  public static class LocalMetadata {
    private boolean generated = true;

    private String locationUrl;

    public boolean isGenerated() {
      return generated;
    }

    public void setGenerated(boolean generated) {
      this.generated = generated;
    }

    public String getLocationUrl() {
      return locationUrl;
    }

    public void setLocationUrl(String locationUrl) {
      this.locationUrl = locationUrl;
    }
  }
  
  public enum SSONameIDType {

    UNSPECIFIED(NameIDType.UNSPECIFIED),
    EMAIL(NameIDType.EMAIL),
    X509_SUBJECT(NameIDType.X509_SUBJECT),
    KERBEROS(NameIDType.KERBEROS),
    ENTITY(NameIDType.ENTITY),
    PERSISTENT(NameIDType.PERSISTENT),
    TRANSIENT(NameIDType.TRANSIENT);
    
    private final String type;

    private SSONameIDType(String t) {
      type = t;
    }

    public String type() {
      return type;
    }

  }

  public enum HostnameVerificationMode {
    DEFAULT("default"),
    DEFAULT_AND_LOCALHOST("defaultAndLocalhost"),
    STRICT("strict"),
    ALLOW_ALL("allowAll");

    private String mode;

    private HostnameVerificationMode(String m) {
      this.mode = m;
    }

    public String mode() {
      return mode;
    }
  }

  private String entityId;

  private String keystore;

  private String keystorePassword;

  private String keyId;

  private String keyPassword;

  private String idResolvers;

  private int maxAssertionTimeSec;

  private int maxAuthenticationAgeSec;

  private long metadataRefreshPeriodSec = TimeUnit.HOURS.toSeconds(12);
  
  private String idpEntityIdWhilelist;

  private List<IamSamlIdpMetadataProperties> idpMetadata;

  @Valid
  private List<IamSamlLoginShortcut> loginShortcuts;

  private LoginButtonProperties wayfLoginButton;

  private HostnameVerificationMode hostnameVerificationMode = HostnameVerificationMode.DEFAULT;
  
  private SSONameIDType nameidPolicy = SSONameIDType.TRANSIENT;

  private LocalMetadata localMetadata = new LocalMetadata();
  
  private SignatureProperties signature = new SignatureProperties();
  
  private List<ProfileProperties> customProfile = Lists.newArrayList();
 
  private List<RegistrationMappingProperties> customMapping = Lists.newArrayList();
  
  private ValidatorProperties defaultValidator;
  
  private List<IssuerValidationProperties> validators = Lists.newArrayList();
  
  private long httpClientConnectionTimeoutSecs = 5;
  private long httpClientSocketTimeoutSecs = 5;
  
  
  public List<IamSamlIdpMetadataProperties> getIdpMetadata() {
    return idpMetadata;
  }

  public void setIdpMetadata(List<IamSamlIdpMetadataProperties> idpMetadata) {
    this.idpMetadata = idpMetadata;
  }

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
  }

  public String getKeystore() {
    return keystore;
  }

  public void setKeystore(String keystore) {
    this.keystore = keystore;
  }

  public String getKeystorePassword() {
    return keystorePassword;
  }

  public void setKeystorePassword(String keystorePassword) {
    this.keystorePassword = keystorePassword;
  }

  public String getKeyId() {
    return keyId;
  }

  public void setKeyId(String keyId) {
    this.keyId = keyId;
  }

  public String getKeyPassword() {
    return keyPassword;
  }

  public void setKeyPassword(String keyPassword) {
    this.keyPassword = keyPassword;
  }

  public int getMaxAssertionTimeSec() {
    return maxAssertionTimeSec;
  }

  public void setMaxAssertionTimeSec(int maxAssertionTimeSec) {
    this.maxAssertionTimeSec = maxAssertionTimeSec;
  }

  public int getMaxAuthenticationAgeSec() {
    return maxAuthenticationAgeSec;
  }

  public void setMaxAuthenticationAgeSec(int maxAuthenticationAgeSec) {
    this.maxAuthenticationAgeSec = maxAuthenticationAgeSec;
  }

  public String getIdResolvers() {
    return idResolvers;
  }

  public void setIdResolvers(String idResolvers) {
    this.idResolvers = idResolvers;
  }


  public String getIdpEntityIdWhilelist() {
    return idpEntityIdWhilelist;
  }

  public void setIdpEntityIdWhilelist(String idpEntityIdWhilelist) {
    this.idpEntityIdWhilelist = idpEntityIdWhilelist;
  }

  public List<IamSamlLoginShortcut> getLoginShortcuts() {
    return loginShortcuts;
  }

  public void setLoginShortcuts(List<IamSamlLoginShortcut> loginShortcuts) {
    this.loginShortcuts = loginShortcuts;
  }

  public LoginButtonProperties getWayfLoginButton() {
    return wayfLoginButton;
  }

  public void setWayfLoginButton(LoginButtonProperties wayfLoginButton) {
    this.wayfLoginButton = wayfLoginButton;
  }

  public HostnameVerificationMode getHostnameVerificationMode() {
    return hostnameVerificationMode;
  }

  public void setHostnameVerificationMode(HostnameVerificationMode hostnameVerificationMode) {
    this.hostnameVerificationMode = hostnameVerificationMode;
  }

  public SSONameIDType getNameidPolicy() {
    return nameidPolicy;
  }
  
  public void setNameidPolicy(SSONameIDType nameidPolicy) {
    this.nameidPolicy = nameidPolicy;
  }

  public long getMetadataRefreshPeriodSec() {
    return metadataRefreshPeriodSec;
  }

  public void setMetadataRefreshPeriodSec(long metadataRefreshPeriodSec) {
    this.metadataRefreshPeriodSec = metadataRefreshPeriodSec;
  }
  
  public LocalMetadata getLocalMetadata() {
    return localMetadata;
  }
  
  public void setLocalMetadata(LocalMetadata localMetadata) {
    this.localMetadata = localMetadata;
  }
  
  public SignatureProperties getSignature() {
    return signature;
  }
  
  public void setSignature(SignatureProperties signature) {
    this.signature = signature;
  }

  public List<ProfileProperties> getCustomProfile() {
    return customProfile;
  }

  public void setCustomProfile(List<ProfileProperties> customProfile) {
    this.customProfile = customProfile;
  }

  public List<RegistrationMappingProperties> getCustomMapping() {
    return customMapping;
  }

  public void setCustomMapping(List<RegistrationMappingProperties> customMapping) {
    this.customMapping = customMapping;
  }

  public ValidatorProperties getDefaultValidator() {
    return defaultValidator;
  }

  public void setDefaultValidator(ValidatorProperties defaultValidator) {
    this.defaultValidator = defaultValidator;
  }

  public List<IssuerValidationProperties> getValidators() {
    return validators;
  }

  public void setValidators(List<IssuerValidationProperties> validators) {
    this.validators = validators;
  }

  public long getHttpClientConnectionTimeoutSecs() {
    return httpClientConnectionTimeoutSecs;
  }

  public void setHttpClientConnectionTimeoutSecs(long httpClientConnectionTimeoutSecs) {
    this.httpClientConnectionTimeoutSecs = httpClientConnectionTimeoutSecs;
  }

  public long getHttpClientSocketTimeoutSecs() {
    return httpClientSocketTimeoutSecs;
  }

  public void setHttpClientSocketTimeoutSecs(long httpClientSocketTimeoutSecs) {
    this.httpClientSocketTimeoutSecs = httpClientSocketTimeoutSecs;
  }
}
