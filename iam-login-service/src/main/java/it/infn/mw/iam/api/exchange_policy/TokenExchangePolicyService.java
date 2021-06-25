package it.infn.mw.iam.api.exchange_policy;

import java.util.List;

public interface TokenExchangePolicyService {

  List<ExchangePolicyDTO> getTokenExchangePolicies();

  ExchangePolicyDTO getTokenExchangePolicyById(Long policyId);

  ExchangePolicyDTO createTokenExchangePolicy(ExchangePolicyDTO policy);

  void deleteTokenExchangePolicyById(Long policyId);

  void clearTokenExchangePolicyCache();
}
