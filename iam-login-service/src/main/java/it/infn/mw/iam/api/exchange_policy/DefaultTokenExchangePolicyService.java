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
package it.infn.mw.iam.api.exchange_policy;

import java.time.Clock;
import java.util.Date;
import java.util.Optional;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;

@Service
@Transactional
public class DefaultTokenExchangePolicyService implements TokenExchangePolicyService {

  private final IamTokenExchangePolicyRepository repo;
  private final ExchangePolicyConverter converter;
  private final Clock clock;
  private final TokenExchangePdp pdp;

  @Autowired
  public DefaultTokenExchangePolicyService(IamTokenExchangePolicyRepository repo,
      ExchangePolicyConverter converter, Clock clock, TokenExchangePdp pdp) {
    this.repo = repo;
    this.converter = converter;
    this.clock = clock;
    this.pdp = pdp;
  }

  private Supplier<ExchangePolicyNotFoundError> notFoundError(Long id) {
    return () -> new ExchangePolicyNotFoundError("Exchange policy not found for id: " + id);
  }

  @Override
  public Page<ExchangePolicyDTO> getTokenExchangePolicies(Pageable page) {
    return repo.findAll(page).map(converter::dtoFromEntity);
  }

  @Override
  public void deleteTokenExchangePolicyById(Long id) {
    IamTokenExchangePolicyEntity policy = repo.findById(id).orElseThrow(notFoundError(id));

    repo.delete(policy);

    pdp.reloadPolicies();
  }

  @Override
  public Optional<ExchangePolicyDTO> getTokenExchangePolicyById(Long id) {
    return repo.findById(id).map(converter::dtoFromEntity);
  }

  @Override
  public ExchangePolicyDTO createTokenExchangePolicy(ExchangePolicyDTO policy) {

    Date now = Date.from(clock.instant());
    IamTokenExchangePolicyEntity policyEntity = converter.entityFromDto(policy);

    policyEntity.setCreationTime(now);
    policyEntity.setLastUpdateTime(now);

    policyEntity = repo.save(policyEntity);

    pdp.reloadPolicies();

    return converter.dtoFromEntity(policyEntity);
  }

  @Override
  public void deleteAllTokenExchangePolicies() {
    repo.deleteAll();
    pdp.reloadPolicies();
  }

}
