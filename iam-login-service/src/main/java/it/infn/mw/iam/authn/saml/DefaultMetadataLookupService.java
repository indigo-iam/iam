package it.infn.mw.iam.authn.saml;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.samlext.saml2mdui.Logo;
import org.opensaml.samlext.saml2mdui.UIInfo;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

import it.infn.mw.iam.authn.saml.model.IdpDescription;

@Component
@Profile("saml")
public class DefaultMetadataLookupService implements MetadataLookupService {

  private static final int MAX_RESULTS = 20;
  private static final Logger LOG = LoggerFactory.getLogger(DefaultMetadataLookupService.class);

  Set<IdpDescription> descriptions = new HashSet<>();

  MetadataManager metadataManager;

  @Autowired
  public DefaultMetadataLookupService(MetadataManager manager) {
    this.metadataManager = manager;
    try {
      initializeMetadataSet();
    } catch (MetadataProviderException e) {
      throw new IllegalStateException(e);
    }
  }

  private void initializeMetadataSet() throws MetadataProviderException {

    for (String idpName : metadataManager.getIDPEntityNames()) {
      descriptions.add(descriptionFromMetadata(metadataManager.getEntityDescriptor(idpName)));
    }

  }

  private IdpDescription descriptionFromMetadata(EntityDescriptor descriptor) {
    IdpDescription result = new IdpDescription();
    result.setEntityId(descriptor.getEntityID());

    IDPSSODescriptor idpDesc = descriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (idpDesc != null) {
      if (idpDesc.getExtensions() != null) {

        for (final XMLObject object : idpDesc.getExtensions()
          .getUnknownXMLObjects(UIInfo.DEFAULT_ELEMENT_NAME)) {
          if (object instanceof UIInfo) {
            UIInfo uiInfo = (UIInfo) object;

            if (!uiInfo.getDisplayNames().isEmpty()) {
              result
                .setOrganizationName(uiInfo.getDisplayNames().get(0).getName().getLocalString());
            }

            if (!uiInfo.getLogos().isEmpty()) {

              Logo minLogo =
                  uiInfo.getLogos().stream().min(Comparator.comparing(Logo::getHeight)).get();

              result.setImageUrl(minLogo.getURL());
            }
          }
        }
      }
    }

    if (result.getOrganizationName() == null || result.getOrganizationName().isEmpty()) {
      result.setOrganizationName(result.getEntityId());
    }

    return result;
  }



  @Override
  public List<IdpDescription> lookupIdp(String text) {

    // Try entityId match
    try {

      EntityDescriptor entityDescriptor = metadataManager.getEntityDescriptor(text);
      if (entityDescriptor != null) {
        return ImmutableList.of(descriptionFromMetadata(entityDescriptor));
      }

    } catch (MetadataProviderException e) {
      throw new RuntimeException(e);
    }

    return descriptions.stream()
      .filter(p -> p.getOrganizationName() != null
          && p.getOrganizationName().toLowerCase().contains(text.toLowerCase()))
      .limit(MAX_RESULTS)
      .collect(Collectors.toList());

  }

  @Override
  public List<IdpDescription> listIdps() {
    Set<String> idpNames = metadataManager.getIDPEntityNames();

    List<IdpDescription> results = new ArrayList<>();

    for (String idpName : idpNames) {
      try {
        IdpDescription desc = descriptionFromMetadata(metadataManager.getEntityDescriptor(idpName));

        if (!Strings.isNullOrEmpty(desc.getOrganizationName())) {
          results.add(desc);
        }

      } catch (MetadataProviderException e) {
        LOG.warn("Error accessing metadata for entity: {}", idpName, e);
        continue;
      }

    }

    return results;

  }


}
