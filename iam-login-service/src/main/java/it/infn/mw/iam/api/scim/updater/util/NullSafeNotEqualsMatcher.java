package it.infn.mw.iam.api.scim.updater.util;

import java.util.function.Predicate;
import java.util.function.Supplier;

public class NullSafeNotEqualsMatcher<T> implements Predicate<T> {

  final Supplier<T> supplier;


  public NullSafeNotEqualsMatcher(Supplier<T> supplier) {
    this.supplier = supplier;
  }

  @Override
  public boolean test(T t) {

    if (supplier.get() == null && t == null) {
      return false;
    }
    if (supplier.get() == null) {
      return true;
    }

    return !supplier.get().equals(t);

  }

}
