package it.infn.mw.iam.audit.events.tokens;

public class HeaderDTO {

  private String kid;
  private String alg;

  public String getKid() {
    return kid;
  }

  public void setKid(String kid) {
    this.kid = kid;
  }

  public String getAlg() {
    return alg;
  }

  public void setAlg(String alg) {
    this.alg = alg;
  }


}
