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
package it.infn.mw.iam.authn;

import java.util.List;
import java.util.Objects;

import it.infn.mw.iam.config.oidc.OidcProvider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.error.InvalidAARCHintError;
import it.infn.mw.iam.authn.saml.DefaultMetadataLookupService;
import it.infn.mw.iam.authn.saml.model.IdpDescription;
import it.infn.mw.iam.config.oidc.OidcValidatedProviders;

@Service
public class DefaultAARCHintService implements AARCHintService {

  private String baseUrl;

  private OidcValidatedProviders oidcProviders;

  private DefaultMetadataLookupService samlProviders;


  @Autowired
  public DefaultAARCHintService(@Value("${iam.baseUrl}") String url,
      OidcValidatedProviders oidcProvicers) {
    this.baseUrl = url;
    this.oidcProviders = oidcProvicers;
  }

  protected void hintSanityChecks(String hint) {
    if (Objects.isNull(hint)) {
      throw new InvalidAARCHintError("null hint");
    }

    if (Strings.isNullOrEmpty(hint.trim())) {
      throw new InvalidAARCHintError("empty hint");
    }
  }

  @Autowired
  public void setSaml(@Lazy DefaultMetadataLookupService samlProviders) {
    this.samlProviders = samlProviders;
  }

  @Override
  public String resolve(String aarcHint) {
    hintSanityChecks(aarcHint);

    int indexOfNestedHints = aarcHint.indexOf('?');

    // Currently not accepting the nested hint parameters
    String aarcHintEntityID =
        (indexOfNestedHints != -1) ? aarcHint.substring(0, indexOfNestedHints) : aarcHint;

    List<OidcProvider> availableOidcProviders = oidcProviders.getValidatedProviders();
    List<IdpDescription> availableSamlProviders = samlProviders.listIdps();

    // OIDC redirect
    if (availableOidcProviders.stream()
      .anyMatch(provider -> provider.getIssuer().equals(aarcHintEntityID))) {

      return String.format("%s/openid_connect_login?iss=%s", baseUrl, aarcHintEntityID);

      // SAML redirect
    } else if (availableSamlProviders.stream()
      .anyMatch(provider -> provider.getEntityId().equals(aarcHintEntityID))) {

      return String.format("%s/saml/login?idp=%s", baseUrl, aarcHintEntityID);

    } else {

      throw new InvalidAARCHintError(String.format("unsupported hint: %s", aarcHintEntityID));
    }
  }
}

