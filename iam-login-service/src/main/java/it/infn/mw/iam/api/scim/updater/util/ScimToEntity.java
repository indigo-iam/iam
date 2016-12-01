package it.infn.mw.iam.api.scim.updater.util;

@FunctionalInterface
public interface ScimToEntity<ScimType, EntityType> {

  EntityType fromScim(ScimType s);
}
