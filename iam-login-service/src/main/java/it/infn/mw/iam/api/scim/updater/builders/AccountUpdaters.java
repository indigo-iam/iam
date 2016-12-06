package it.infn.mw.iam.api.scim.updater.builders;

import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class AccountUpdaters {

  public static Adders adders(IamAccountRepository repo, PasswordEncoder encoder,
      IamAccount account) {
    return new Adders(repo, encoder, account);
  }

  public static Removers removers(IamAccountRepository repo, IamAccount account) {
    return new Removers(repo, account);
  }

  public static Replacers replacers(IamAccountRepository repo, PasswordEncoder encoder,
      IamAccount account) {
    return new Replacers(repo, encoder, account);
  }

}