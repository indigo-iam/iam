package it.infn.mw.iam.api.account_linking;

import static it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType.SAML;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.audit.events.AccountLinkEvent;
import it.infn.mw.iam.audit.events.AccountUnlinkEvent;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
public class DefaultAccountLinkingService
    implements AccountLinkingService, ApplicationEventPublisherAware {

  final IamAccountRepository iamAccountRepository;
  final ExternalAccountLinker externalAccountLinker;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultAccountLinkingService(IamAccountRepository repo, ExternalAccountLinker linker) {
    this.iamAccountRepository = repo;
    this.externalAccountLinker = linker;
  }

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  private IamAccount findAccount(Principal authenticatedUser) {
    return iamAccountRepository.findByUsername(authenticatedUser.getName()).orElseThrow(() -> {
      return new UsernameNotFoundException(
          "No user found with username '" + authenticatedUser.getName() + "'");
    });
  }

  @Override
  public void linkExternalAccount(Principal authenticatedUser,
      AbstractExternalAuthenticationToken<?> externalAuthenticationToken) {

    IamAccount userAccount = findAccount(authenticatedUser);

    externalAuthenticationToken.linkToIamAccount(externalAccountLinker, userAccount);

    eventPublisher.publishEvent(new AccountLinkEvent(this, userAccount,
        externalAuthenticationToken.toExernalAuthenticationInfo(),
        String.format("User %s has linked a new account of type %s", userAccount.getUsername(),
            externalAuthenticationToken.toExernalAuthenticationInfo().getType().toString())));
  }


  @Override
  public void unlinkExternalAccount(Principal authenticatedUser, ExternalAuthenticationType type,
      String iss, String sub) {

    IamAccount userAccount = findAccount(authenticatedUser);

    boolean modified = false;
    if (SAML.equals(type)) {

      IamSamlId id = new IamSamlId();
      id.setIdpId(iss);
      id.setUserId(sub);

      userAccount.getSamlIds()
        .stream()
        .filter(o -> o.equals(id))
        .findFirst()
        .ifPresent(i -> i.setAccount(null));

      modified = userAccount.getSamlIds().remove(id);

    } else {

      IamOidcId id = new IamOidcId();
      id.setIssuer(iss);
      id.setSubject(sub);

      userAccount.getOidcIds()
        .stream()
        .filter(o -> o.equals(id))
        .findFirst()
        .ifPresent(i -> i.setAccount(null));

      modified = userAccount.getOidcIds().remove(id);
    }

    if (modified) {
      userAccount.touch();
      iamAccountRepository.save(userAccount);

      eventPublisher.publishEvent(new AccountUnlinkEvent(this, userAccount, type, iss, sub,
          String.format("User %s has unlinked an account of type %s", userAccount.getUsername(),
              type.toString())));
    }
  }

}
