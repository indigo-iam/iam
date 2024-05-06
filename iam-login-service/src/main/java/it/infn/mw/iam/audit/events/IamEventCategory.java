package it.infn.mw.iam.audit.events;

public enum IamEventCategory {
  NONE,
  ACCOUNT,
  GROUP,
  REGISTRATION,
  AUTHENTICATION,
  AUTHORIZATION,
  SCOPE_POLICY,
  AUP,
  MEMBERSHIP,
  CLIENT,
  TOKEN
}