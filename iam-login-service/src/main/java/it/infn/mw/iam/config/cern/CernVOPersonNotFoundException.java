package it.infn.mw.iam.config.cern;

public class CernVOPersonNotFoundException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public CernVOPersonNotFoundException(String message) {
    super(message);
}
}
