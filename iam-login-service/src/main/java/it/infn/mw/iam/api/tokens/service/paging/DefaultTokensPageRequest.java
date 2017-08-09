package it.infn.mw.iam.api.tokens.service.paging;

public class DefaultTokensPageRequest implements TokensPageRequest {

  private final int count;
  private final int startIndex;

  private DefaultTokensPageRequest(Builder b) {
    this.count = b.count;
    this.startIndex = b.startIndex;
  }

  @Override
  public int getCount() {

    return count;
  }

  @Override
  public int getStartIndex() {

    return startIndex;
  }

  public static class Builder {

    private int count;
    private int startIndex;

    public Builder count(int count) {

      this.count = count;
      return this;
    }

    public Builder startIndex(int startIndex) {

      this.startIndex = startIndex;
      return this;
    }

    public DefaultTokensPageRequest build() {

      return new DefaultTokensPageRequest(this);
    }
  }
}
