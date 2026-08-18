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
package it.infn.mw.iam.core.oauth.scope.pdp;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.config.IamProperties.OpaProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.OpaRequest.Client;
import it.infn.mw.iam.core.oauth.scope.pdp.OpaRequest.User;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;

public class OpaScopePolicyEngine extends DefaultScopePolicyEngine {
  public static final Logger LOG = LoggerFactory.getLogger(OpaScopePolicyEngine.class);

  private RestTemplate restTemplate;
  private OpaProperties opaProperties;

  public OpaScopePolicyEngine(IamScopePolicyRepository policyRepo,
      RestTemplateFactory restTemplateFactory, OpaProperties opaProperties) {
    super(policyRepo);
    this.restTemplate = restTemplateFactory.newRestTemplate();
    this.opaProperties = opaProperties;
  }

  @Override
  public Set<String> apply(Set<String> requestedScopes, IamAccount account, String clientId) {

    Set<String> userGroups =
        account.getGroups().stream().map(ag -> ag.getGroup().getName()).collect(Collectors.toSet());
    OpaRequest request =
        new OpaRequest(new User(account.getUuid(), userGroups),
            new Client(clientId), requestedScopes);

    Optional<OpaResponse> response = evaluatePolicy(request);
    if (response.isPresent()) {
      return response.get().filtered_scopes();
    } else {
      return super.apply(requestedScopes, account, clientId);
    }
  }

  public Optional<OpaResponse> evaluatePolicy(@RequestBody OpaRequest payload) {
    try {
      String opaUrl = opaProperties.getUrl();
      ResponseEntity<OpaResponse> response =
          restTemplate.postForEntity(opaUrl, payload, OpaResponse.class);

      LOG.info("OPA response status code: {}", response.getStatusCode());
      if (response.getStatusCode() == HttpStatus.OK) {

        Optional<OpaResponse> body = Optional.ofNullable(response.getBody());
        LOG.debug("OPA response body: {}", response.getBody());

        return body;
      }

      return Optional.empty();
    } catch (RestClientException e) {

      LOG.info("Error retrieving OPA response: {}", e.getMessage());
      return Optional.empty();
    }
  }
}
