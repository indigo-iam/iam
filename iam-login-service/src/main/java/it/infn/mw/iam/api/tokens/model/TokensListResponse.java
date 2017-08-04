package it.infn.mw.iam.api.tokens.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

public class TokensListResponse<T> {

  private long totalResults;
  private long itemsPerPage;
  private long startIndex;
  private List<T> resources = new ArrayList<>();

  public TokensListResponse() {}

  public TokensListResponse(List<T> resources, long totalResults, long itemsPerPage,
      long startIndex) {

    this.resources = resources;
    this.totalResults = totalResults;
    this.itemsPerPage = itemsPerPage;
    this.startIndex = startIndex;
  }

  public long getTotalResults() {

    return totalResults;
  }

  public long getItemsPerPage() {

    return itemsPerPage;
  }

  public long getStartIndex() {

    return startIndex;
  }

  @JsonProperty("Resources")
  public List<T> getResources() {

    return resources;
  }
}
