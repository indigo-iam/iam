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

import static com.google.common.collect.Lists.newArrayList;
import static java.util.stream.Collectors.toSet;

import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.converter.Converter;
import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.model.IamTokenExchangeScopePolicy;

@Service
public class ExchangePolicyConverter
    implements Converter<ExchangePolicyDTO, IamTokenExchangePolicyEntity> {

  protected ExchangeScopePolicyDTO dtoFromScopePolicy(IamTokenExchangeScopePolicy sp) {
    ExchangeScopePolicyDTO dto = new ExchangeScopePolicyDTO();
    dto.setType(sp.getType());
    dto.setRule(sp.getRule());
    dto.setMatchParam(sp.getMatchParam());
    return dto;
  }
  
  protected IamTokenExchangeScopePolicy scopePolicyFromDto(ExchangeScopePolicyDTO dto) {
    IamTokenExchangeScopePolicy sp = new IamTokenExchangeScopePolicy();
    sp.setType(dto.getType());
    sp.setRule(dto.getRule());
    sp.setMatchParam(dto.getMatchParam());
    return sp;
  }

  @Override
  public IamTokenExchangePolicyEntity entityFromDto(ExchangePolicyDTO dto) {

    IamTokenExchangePolicyEntity entity = new IamTokenExchangePolicyEntity();
    entity.setDescription(dto.getDescription());
    entity.setRule(dto.getRule());
    IamClientMatchingPolicy originClient = new IamClientMatchingPolicy();
    originClient.setType(dto.getOriginClient().getType());
    originClient.setMatchParam(dto.getOriginClient().getMatchParam());

    entity.setOriginClient(originClient);

    IamClientMatchingPolicy destinationClient = new IamClientMatchingPolicy();
    destinationClient.setType(dto.getDestinationClient().getType());
    destinationClient.setMatchParam(dto.getDestinationClient().getMatchParam());

    entity.setDestinationClient(destinationClient);

    Set<IamTokenExchangeScopePolicy> scopePolicies =
        dto.getScopePolicies().stream().map(this::scopePolicyFromDto).collect(toSet());
    
    entity.setScopePolicies(scopePolicies);
    
    return entity;
  }

  @Override
  public ExchangePolicyDTO dtoFromEntity(IamTokenExchangePolicyEntity entity) {
    ExchangePolicyDTO dto = new ExchangePolicyDTO();

    dto.setId(entity.getId());

    dto.setRule(entity.getRule());

    dto.setCreationTime(entity.getCreationTime());
    dto.setDescription(entity.getDescription());
    dto.setLastUpdateTime(entity.getLastUpdateTime());

    ClientMatchingPolicyDTO origin = new ClientMatchingPolicyDTO();
    origin.setType(entity.getOriginClient().getType());
    origin.setMatchParam(entity.getOriginClient().getMatchParam());

    dto.setOriginClient(origin);

    ClientMatchingPolicyDTO destination = new ClientMatchingPolicyDTO();
    destination.setType(entity.getDestinationClient().getType());
    destination.setMatchParam(entity.getDestinationClient().getMatchParam());

    dto.setDestinationClient(destination);

    List<ExchangeScopePolicyDTO> scopePolicies = newArrayList();

    for (IamTokenExchangeScopePolicy p : entity.getScopePolicies()) {
      scopePolicies.add(dtoFromScopePolicy(p));
    }
    
    dto.setScopePolicies(scopePolicies);

    return dto;
  }
}
