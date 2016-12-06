package it.infn.mw.iam.api.scim.updater.util;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.function.BiConsumer;
import java.util.function.Predicate;

import it.infn.mw.iam.persistence.model.IamAccount;

public class IdNotBoundChecker<T> implements Predicate<T> {

  final IamAccount account;
  final AccountFinder<T> finder;
  final BiConsumer<T, IamAccount> action;


  public IdNotBoundChecker(AccountFinder<T> finder, IamAccount account,
      BiConsumer<T, IamAccount> action) {

    this.finder = finder;
    this.account = account;
    this.action = action;
  }


  @Override
  public boolean test(T id) {
    checkNotNull(id);

    finder.find(id).ifPresent(otherAccount -> {
      if (!otherAccount.equals(account)) {
        action.accept(id, account);
      }
    });

    return true;
  }
}
