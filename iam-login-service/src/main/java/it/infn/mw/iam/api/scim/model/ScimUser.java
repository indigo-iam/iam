package it.infn.mw.iam.api.scim.model;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.validation.Valid;

import org.hibernate.validator.constraints.NotBlank;
import org.hibernate.validator.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Preconditions;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonFilter("attributeFilter")
public class ScimUser extends ScimResource {

  public interface NewUserValidation {
  };

  public interface UpdateUserValidation {
  };

  public static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
  public static final String RESOURCE_TYPE = "User";

  @NotBlank(groups = {NewUserValidation.class})
  private final String userName;

  @JsonFilter("passwordFilter")
  private final String password;

  @Valid
  private final ScimName name;

  private final String displayName;
  private final String nickName;
  private final String profileUrl;
  private final String title;
  private final String userType;
  private final String preferredLanguage;
  private final String locale;
  private final String timezone;
  private final Boolean active;

  @NotEmpty(groups = {NewUserValidation.class})
  @Valid
  private final List<ScimEmail> emails;

  private final List<ScimAddress> addresses;
  private final List<ScimPhoto> photos;
  private final List<ScimX509Certificate> x509Certificates;

  private final Set<ScimGroupRef> groups;

  private final ScimIndigoUser indigoUser;

  @JsonCreator
  private ScimUser(@JsonProperty("id") String id, @JsonProperty("externalId") String externalId,
      @JsonProperty("meta") ScimMeta meta, @JsonProperty("schemas") Set<String> schemas,
      @JsonProperty("userName") String userName, @JsonProperty("password") String password,
      @JsonProperty("name") ScimName name, @JsonProperty("displayName") String displayName,
      @JsonProperty("nickName") String nickName, @JsonProperty("profileUrl") String profileUrl,
      @JsonProperty("picture") String picture, @JsonProperty("title") String title,
      @JsonProperty("userType") String userType,
      @JsonProperty("preferredLanguage") String preferredLanguage,
      @JsonProperty("locale") String locale, @JsonProperty("timezone") String timezone,
      @JsonProperty("active") Boolean active, @JsonProperty("emails") List<ScimEmail> emails,
      @JsonProperty("addresses") List<ScimAddress> addresses,
      @JsonProperty("photos") List<ScimPhoto> photos,
      @JsonProperty("groups") Set<ScimGroupRef> groups,
      @JsonProperty("x509Certificates") List<ScimX509Certificate> x509Certificates,
      @JsonProperty(INDIGO_USER_SCHEMA) ScimIndigoUser indigoUser) {

    super(id, externalId, meta, schemas);

    this.userName = userName;
    this.password = password;
    this.name = name;
    this.displayName = displayName;
    this.nickName = nickName;
    this.profileUrl = profileUrl;
    this.photos = photos;
    this.title = title;
    this.userType = userType;
    this.preferredLanguage = preferredLanguage;
    this.locale = locale;
    this.timezone = timezone;
    this.emails = emails;
    this.active = active;
    this.groups = groups;
    this.addresses = addresses;
    this.indigoUser = indigoUser;
    this.x509Certificates = x509Certificates;

  }

  private ScimUser(Builder b) {
    super(b);
    this.userName = b.userName;
    this.name = b.name;
    this.displayName = b.displayName;
    this.nickName = b.nickName;
    this.profileUrl = b.profileUrl;
    this.photos = b.photos;
    this.title = b.title;
    this.userType = b.userType;
    this.preferredLanguage = b.preferredLanguage;
    this.locale = b.locale;
    this.timezone = b.timezone;
    this.active = b.active;
    this.emails = b.emails;
    this.addresses = b.addresses;
    this.x509Certificates = b.x509Certificates;
    this.indigoUser = b.indigoUser;
    this.groups = b.groups;
    this.password = b.password;
  }

  public String getUserName() {

    return userName;
  }

  public String getPassword() {
    return password;
  }

  public ScimName getName() {

    return name;
  }

  public String getDisplayName() {

    return displayName;
  }

  public String getNickName() {

    return nickName;
  }

  public String getProfileUrl() {

    return profileUrl;
  }

  public boolean hasPhotos() {

    return photos != null && !photos.isEmpty();
  }

  public List<ScimPhoto> getPhotos() {

    return photos;
  }

  public String getTitle() {

    return title;
  }

  public String getUserType() {

    return userType;
  }

  public String getPreferredLanguage() {

    return preferredLanguage;
  }

  public String getLocale() {

    return locale;
  }

  public String getTimezone() {

    return timezone;
  }

  public Boolean getActive() {

    return active;
  }

  public List<ScimEmail> getEmails() {

    return emails;
  }

  public boolean hasAddresses() {

    return addresses != null && !addresses.isEmpty();
  }

  public List<ScimAddress> getAddresses() {

    return addresses;
  }

  public List<ScimX509Certificate> getX509Certificates() {

    return x509Certificates;
  }

  @JsonProperty(value = ScimConstants.INDIGO_USER_SCHEMA)
  public ScimIndigoUser getIndigoUser() {

    return indigoUser;
  }

  public Set<ScimGroupRef> getGroups() {

    return groups;
  }

  public boolean hasX509Certificates() {

    return x509Certificates != null && !x509Certificates.isEmpty();
  }

  public boolean hasOidcIds() {

    return indigoUser != null && indigoUser.getOidcIds() != null
        && !indigoUser.getOidcIds().isEmpty();
  }

  public boolean hasSshKeys() {

    return indigoUser != null && indigoUser.getSshKeys() != null
        && !indigoUser.getSshKeys().isEmpty();
  }

  public boolean hasSamlIds() {

    return indigoUser != null && indigoUser.getSamlIds() != null
        && !indigoUser.getSamlIds().isEmpty();
  }

  public boolean hasEmails() {

    return emails != null && !emails.isEmpty();
  }

  public boolean hasName() {

    return name != null;
  }

  public static Builder builder(String username) {

    return new Builder(username);
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder extends ScimResource.Builder<ScimUser> {

    private String userName;
    private String password;
    private ScimName name;
    private String displayName;
    private String nickName;
    private String profileUrl;
    private String title;
    private String userType;
    private String preferredLanguage;
    private String locale;
    private String timezone;
    private Boolean active;

    private List<ScimEmail> emails = new ArrayList<ScimEmail>();
    private Set<ScimGroupRef> groups = new LinkedHashSet<ScimGroupRef>();
    private List<ScimAddress> addresses = new ArrayList<ScimAddress>();
    private List<ScimPhoto> photos = new ArrayList<ScimPhoto>();
    private List<ScimX509Certificate> x509Certificates = new ArrayList<ScimX509Certificate>();
    private ScimIndigoUser indigoUser;

    public Builder() {
      super();
    }

    public Builder(String userName) {
      this();
      schemas.add(USER_SCHEMA);
      schemas.add(INDIGO_USER_SCHEMA);
      this.userName = userName;
    }

    public Builder userName(String userName) {

      this.userName = userName;
      return this;
    }

    public Builder password(String password) {
      this.password = password;
      return this;
    }

    public Builder id(String uuid) {

      this.id = uuid;
      return this;
    }

    public Builder meta(ScimMeta meta) {

      this.meta = meta;
      return this;
    }

    public Builder name(ScimName name) {

      this.name = name;
      return this;
    }

    public Builder displayName(String displayName) {

      this.displayName = displayName;
      return this;
    }

    public Builder nickName(String nickName) {

      this.nickName = nickName;
      return this;
    }

    public Builder profileUrl(String profileUrl) {

      this.profileUrl = profileUrl;
      return this;
    }

    public Builder title(String title) {

      this.title = title;
      return this;
    }

    public Builder userType(String userType) {

      this.userType = userType;
      return this;
    }

    public Builder preferredLanguage(String preferredLanguage) {

      this.preferredLanguage = preferredLanguage;
      return this;
    }

    public Builder locale(String locale) {

      this.locale = locale;
      return this;
    }

    public Builder timezone(String timezone) {

      this.timezone = timezone;
      return this;
    }

    public Builder active(Boolean active) {

      this.active = active;
      return this;
    }

    public Builder addGroupRef(ScimGroupRef scimGroupRef) {

      Preconditions.checkNotNull(scimGroupRef, "Null group ref");

      groups.add(scimGroupRef);
      return this;
    }

    public Builder buildEmail(String email) {

      emails.add(ScimEmail.builder().email(email).build());
      return this;
    }

    public Builder buildName(String givenName, String familyName) {

      this.name = ScimName.builder().givenName(givenName).familyName(familyName).build();
      return this;
    }

    public Builder buildPhoto(String value) {

      photos.add(ScimPhoto.builder().value(value).build());
      return this;
    }

    public Builder addPhoto(ScimPhoto scimPhoto) {

      Preconditions.checkNotNull(scimPhoto, "Null photo");

      photos.add(scimPhoto);
      return this;
    }

    public Builder addEmail(ScimEmail scimEmail) {

      Preconditions.checkNotNull(scimEmail, "Null email");

      emails.add(scimEmail);
      return this;
    }

    public Builder indigoUserInfo(ScimIndigoUser indigoUser) {

      this.indigoUser = indigoUser;
      return this;
    }

    public Builder addAddress(ScimAddress scimAddress) {

      addresses.add(scimAddress);
      return this;
    }

    public Builder addX509Certificate(ScimX509Certificate scimX509Certificate) {

      Preconditions.checkNotNull(scimX509Certificate, "Null x509 certificate");

      x509Certificates.add(scimX509Certificate);
      return this;
    }

    public Builder buildX509Certificate(String display, String value, Boolean isPrimary) {

      addX509Certificate(
          ScimX509Certificate.builder().display(display).value(value).primary(isPrimary).build());
      return this;
    }

    public Builder addOidcId(ScimOidcId oidcId) {

      Preconditions.checkNotNull(oidcId, "Null OpenID Connect ID");

      if (indigoUser == null) {
        this.indigoUser = ScimIndigoUser.builder().build();
      }

      indigoUser.getOidcIds().add(oidcId);
      return this;
    }

    public Builder buildOidcId(String issuer, String subject) {

      return addOidcId(ScimOidcId.builder().subject(subject).issuer(issuer).build());
    }

    public Builder addSshKey(ScimSshKey sshKey) {

      Preconditions.checkNotNull(sshKey, "Null ssh key");

      if (indigoUser == null) {
        this.indigoUser = ScimIndigoUser.builder().build();
      }

      indigoUser.getSshKeys().add(sshKey);
      return this;
    }

    public Builder buildSshKey(String label, String key, String fingerprint, boolean isPrimary) {

      return addSshKey(ScimSshKey.builder()
        .display(label)
        .value(key)
        .fingerprint(fingerprint)
        .primary(isPrimary)
        .build());
    }

    public Builder addSamlId(ScimSamlId samlId) {

      Preconditions.checkNotNull(samlId, "Null saml id");

      if (indigoUser == null) {
        this.indigoUser = ScimIndigoUser.builder().build();
      }

      indigoUser.getSamlIds().add(samlId);
      return this;
    }

    public Builder buildSamlId(String idpId, String userId) {

      return addSamlId(ScimSamlId.builder().idpId(idpId).userId(userId).build());
    }

    public ScimUser build() {

      return new ScimUser(this);
    }

  }
}
