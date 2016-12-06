package it.infn.mw.iam.api.scim.updater.builders;

import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public abstract class AccountBuilderSupport {

  protected final IamAccountRepository repo;
  protected final PasswordEncoder encoder;
  protected final IamAccount account;

  public AccountBuilderSupport(IamAccountRepository repo, IamAccount account) {
    this(repo, null, account);
  }

  public AccountBuilderSupport(IamAccountRepository repo, PasswordEncoder encoder, IamAccount account) {
    this.repo = repo;
    this.encoder = encoder;
    this.account = account;
  }

}

