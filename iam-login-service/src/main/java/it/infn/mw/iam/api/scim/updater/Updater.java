package it.infn.mw.iam.api.scim.updater;

public interface Updater<T, U> {

  boolean add(T target, U updates);

  boolean remove(T target, U updates);

  boolean replace(T target, U updates);

}
