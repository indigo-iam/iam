package it.infn.mw.iam.api.exchange_policy;

import static java.util.stream.Collectors.toList;
import static java.util.stream.StreamSupport.stream;

import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;

@Service
@Transactional
public class DefaultTokenExchangePolicyService implements TokenExchangePolicyService {

  private final Clock clock;
  private final IamTokenExchangePolicyRepository repo;
  private final ExchangePolicyConverter converter;
  private final TokenExchangePdp pdp;

  @Autowired
  public DefaultTokenExchangePolicyService(Clock clock, IamTokenExchangePolicyRepository repo,
      ExchangePolicyConverter converter, TokenExchangePdp pdp) {
    this.clock = clock;
    this.repo = repo;
    this.converter = converter;
    this.pdp = pdp;
  }

  private Supplier<ExchangePolicyNotFoundError> notFoundError(Long id) {
    return () -> new ExchangePolicyNotFoundError("Exchange policy not found for id: " + id);
  }


  @Override
  public List<ExchangePolicyDTO> getTokenExchangePolicies() {
    return stream(repo.findAll().spliterator(), false).map(converter::dtoFromEntity)
      .collect(toList());
  }

  @Override
  public ExchangePolicyDTO getTokenExchangePolicyById(Long policyId) {

    return Optional.ofNullable(repo.findOne(policyId))
      .map(converter::dtoFromEntity)
      .orElseThrow(notFoundError(policyId));
  }

  @Override
  public ExchangePolicyDTO createTokenExchangePolicy(ExchangePolicyDTO policyDTO) {

    Date now = Date.from(clock.instant());

    IamTokenExchangePolicyEntity policy = converter.entityFromDto(policyDTO);

    policy.setCreationTime(now);
    policy.setLastUpdateTime(now);

    policy = repo.save(policy);

    return converter.dtoFromEntity(policy);
  }

  @Override
  public void deleteTokenExchangePolicyById(Long policyId) {
    IamTokenExchangePolicyEntity p =
        Optional.ofNullable(repo.findOne(policyId)).orElseThrow(notFoundError(policyId));
    repo.delete(p.getId());
  }

  @Override
  public void clearTokenExchangePolicyCache() {
    pdp.clearPolicyCache();
  }

}
