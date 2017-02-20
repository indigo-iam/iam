package it.infn.mw.iam.api.account.authority;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.audit.events.AuthorityAddEvent;
import it.infn.mw.iam.audit.events.AuthorityRemoveEvent;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;

@Service
public class DefaultAccountAuthorityService
    implements AccountAuthorityService, ApplicationEventPublisherAware {

  final IamAuthoritiesRepository authRepo;
  final IamAccountRepository accountRepo;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultAccountAuthorityService(IamAuthoritiesRepository authRepo,
      IamAccountRepository accountRepo) {
    this.authRepo = authRepo;
    this.accountRepo = accountRepo;
  }

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  protected IamAuthority findAuthorityFromString(String authority) {
    checkNotNull(authority, "authority must not be null");

    return authRepo.findByAuthority(authority).orElseThrow(
        () -> new InvalidAuthorityError(String.format("Invalid authority: '%s'", authority)));
  }

  @Override
  public void addAuthorityToAccount(IamAccount account, String authority) {
    checkNotNull(account, "account must not be null");

    IamAuthority iamAuthority = findAuthorityFromString(authority);

    if (account.getAuthorities().contains(iamAuthority)) {
      String msg = String.format("Authority '%s' is already bound to user '%s' (%s)", authority,
          account.getUsername(), account.getUuid());
      throw new AuthorityAlreadyBoundError(msg);
    }

    account.getAuthorities().add(iamAuthority);
    accountRepo.save(account);

    eventPublisher.publishEvent(new AuthorityAddEvent(this, account, authority,
        String.format("Add authority %s to user %s.", authority, account.getUsername())));
  }

  @Override
  public void removeAuthorityFromAccount(IamAccount account, String authority) {
    checkNotNull(account, "account must not be null");
    IamAuthority iamAuthority = findAuthorityFromString(authority);
    account.getAuthorities().remove(iamAuthority);
    accountRepo.save(account);

    eventPublisher.publishEvent(new AuthorityRemoveEvent(this, account, authority,
        String.format("Remove authority %s from user %s.", authority, account.getUsername())));
  }

  @Override
  public Set<String> getAccountAuthorities(IamAccount account) {
    checkNotNull(account, "account must not be null");

    return account.getAuthorities().stream().map(i -> i.getAuthority()).collect(Collectors.toSet());
  }

}
