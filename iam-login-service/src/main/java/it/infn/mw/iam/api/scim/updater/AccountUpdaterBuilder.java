package it.infn.mw.iam.api.scim.updater;

@FunctionalInterface
public interface AccountUpdaterBuilder<T> {
  AccountUpdater build(T value);
}
