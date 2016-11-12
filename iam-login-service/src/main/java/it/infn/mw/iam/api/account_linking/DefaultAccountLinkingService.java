package it.infn.mw.iam.api.account_linking;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
public class DefaultAccountLinkingService implements AccountLinkingService {

  final IamAccountRepository iamAccountRepository;
  final ExternalAccountLinker externalAccountLinker;

  @Autowired
  public DefaultAccountLinkingService(IamAccountRepository repo, ExternalAccountLinker linker) {
    this.iamAccountRepository = repo;
    this.externalAccountLinker = linker;
  }


  @Override
  public void linkExternalAccount(Principal authenticatedUser,
      AbstractExternalAuthenticationToken<?> externalAuthenticationToken) {

    IamAccount userAccount =
	iamAccountRepository.findByUsername(authenticatedUser.getName()).orElseThrow(() -> {
	  return new UsernameNotFoundException(
	      "No user found with username '" + authenticatedUser.getName() + "'");
	});

    externalAuthenticationToken.linkToIamAccount(externalAccountLinker, userAccount);
  }

}
