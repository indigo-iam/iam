package it.infn.mw.iam.api.scim.updater;

import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import it.infn.mw.iam.persistence.model.IamAccount;

public class DefaultAccountUpdater<T> extends DefaultUpdater<T> implements AccountUpdater {

  private final IamAccount account;
  
  public DefaultAccountUpdater(IamAccount account, UpdaterType type, Supplier<T> supplier, Consumer<T> consumer,
      T newVal) {
    super(type, supplier, consumer, newVal);
    this.account = account;
  }

  public DefaultAccountUpdater(IamAccount account, UpdaterType type, Consumer<T> consumer, T newVal,
      Predicate<T> predicate) {
    super(type, consumer, newVal, predicate);
    this.account = account;
  }

  @Override
  public IamAccount getAccount() {
    return this.account;
  }

}
