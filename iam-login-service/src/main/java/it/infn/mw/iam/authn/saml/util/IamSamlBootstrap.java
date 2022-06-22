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
package it.infn.mw.iam.authn.saml.util;

import org.opensaml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.saml.SAMLBootstrap;

public class IamSamlBootstrap extends SAMLBootstrap{

  final String sigAlgoName;
  final String sigAlgoURI;
  final String digestAlgoURI;
  
  public IamSamlBootstrap() {
    this("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, SignatureConstants.ALGO_ID_DIGEST_SHA1);
  }
  
  public IamSamlBootstrap(String signatureAlgoName, String signatureAlgoURI, String digestAlgoURI) {
    this.sigAlgoName = signatureAlgoName;
    this.sigAlgoURI = signatureAlgoURI;
    this.digestAlgoURI = digestAlgoURI;
  }
  
  @Override
  public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory){
    super.postProcessBeanFactory(beanFactory);
    
    BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
    config.registerSignatureAlgorithmURI(sigAlgoName, sigAlgoURI);
    config.setSignatureReferenceDigestMethod(digestAlgoURI); 
  }
}
