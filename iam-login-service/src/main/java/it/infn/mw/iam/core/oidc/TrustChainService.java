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
package it.infn.mw.iam.core.oidc;

import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

@Service
@Profile("openid-federation")
public class TrustChainService {

  private final TrustChainResolver resolver;
  private final TrustChainValidator validator;

  public TrustChainService(TrustChainResolver resolver, TrustChainValidator validator) {
    this.resolver = resolver;
    this.validator = validator;
  }

  public TrustChain validateFromEntityId(String entityId) {
    List<List<EntityStatement>> chain = resolver.resolveFromEntityId(entityId);
    return validator.validateAll(chain);
  }

  public TrustChain validateFromEntityConfiguration(EntityStatement ec) {
    List<List<EntityStatement>> chain = resolver.resolveFromEntityConfiguration(ec);
    return validator.validateAll(chain);
  }

  public TrustChain validateFromProvidedChain(List<EntityStatement> providedChain)
      throws BadJOSEException, JOSEException {
    return validator.validate(providedChain);
  }
}
