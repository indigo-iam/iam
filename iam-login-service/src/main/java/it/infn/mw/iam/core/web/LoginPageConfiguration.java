package it.infn.mw.iam.core.web;

public interface LoginPageConfiguration {

  boolean isGoogleEnabled();

  boolean isGithubEnabled();

  boolean isSamlEnabled();

  boolean isRegistrationEnabled();
}
