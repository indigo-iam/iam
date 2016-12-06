package it.infn.mw.iam.api.scim.updater.util;

import java.util.Collection;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class ScimCollectionConverter<EntityType, ScimType>
    implements Supplier<Collection<EntityType>> {

  final Supplier<Collection<ScimType>> supplier;
  final ScimToEntity<ScimType, EntityType> converter;

  public ScimCollectionConverter(Supplier<Collection<ScimType>> supplier,
      ScimToEntity<ScimType, EntityType> converter) {

    this.supplier = supplier;
    this.converter = converter;
  }

  @Override
  public Collection<EntityType> get() {

    if (supplier.get() == null) {
      return null;
    }

    return supplier.get()
      .stream()
      .filter(Objects::nonNull)
      .map(i -> converter.fromScim(i))
      .collect(Collectors.toList());
  }

}
