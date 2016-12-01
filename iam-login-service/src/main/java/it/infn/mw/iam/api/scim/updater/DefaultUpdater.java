package it.infn.mw.iam.api.scim.updater;

import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.infn.mw.iam.api.scim.updater.util.NullSafeNotEqualsMatcher;

public class DefaultUpdater<T> implements Updater {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultUpdater.class);

  final UpdaterType type;
  final T newValue;
  final Consumer<T> setter;
  final Predicate<T> applyIf;


  public DefaultUpdater(UpdaterType type, Consumer<T> consumer, T newVal,
      Predicate<T> predicate) {

    this.type = type;
    this.newValue = newVal;
    this.setter = consumer;
    this.applyIf = predicate;

  }

  public DefaultUpdater(UpdaterType type, Supplier<T> supplier, Consumer<T> consumer, T newVal) {
    this(type, consumer, newVal, nullSafeNotEqualsMatcher(supplier));

  }

  @Override
  public boolean update() {

    if (applyIf.test(newValue)) {
      LOG.debug("{} applied for value '{}'", type, newValue);
      setter.accept(newValue);
      return true;
    }

    LOG.debug("{} not applied for value '{}'", type, newValue);
    return false;
  }

  private static <T> NullSafeNotEqualsMatcher<T> nullSafeNotEqualsMatcher(Supplier<T> supp) {
    return new NullSafeNotEqualsMatcher<T>(supp);
  }

  @Override
  public UpdaterType getType() {
    return type;
  }
}
