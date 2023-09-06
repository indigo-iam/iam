<%@attribute name="title" required="false"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<!DOCTYPE html>
<html lang="${pageContext.response.locale}">
<head>

<base href="${config.issuer}">

<meta charset="utf-8">
<title>${config.topbarTitle}-${title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<link
  rel="stylesheet"
  href="/webjars/bootstrap/css/bootstrap.min.css"></link>

<link
  rel="stylesheet"
  href="/webjars/angular-ui-select/select.min.css"></link>
  
<link
  rel="stylesheet"
  href="${resourcesPrefix}/iam/css/AdminLTE.css"></link>

<link
  rel="stylesheet"
  href="/webjars/font-awesome/css/font-awesome.css"></link>

<link
  rel="stylesheet"
  href="${resourcesPrefix}/iam/css/skins/skin-blue.css"></link>

<link
  rel="stylesheet"
  href="${resourcesPrefix}/iam/css/ionicons/ionicons.min.css"></link>

<link 
  rel="stylesheet"
  href="${resourcesPrefix}/iam/css/toaster.min.css" />

<link
  rel="stylesheet"
  href="${resourcesPrefix}/iam/css/iam.css"></link>

</head>

<script>
var _accountLinkingMessage = "${accountLinkingMessage}";
var _accountLinkingError = "${accountLinkingError}";

function getUserX509CertficateSubject() {
	return escape("${sessionScope.IAM_X509_CRED.subject}");
}

function getUserX509CertficateIssuer() {
	  return escape("${sessionScope.IAM_X509_CRED.issuer}");
}

//get the info of the currently authenticated user, if available (null otherwise)
function getUserInfo() {
  return ${userInfoJson};
}

// get the authorities of the currently authenticated user, if available (null otherwise)
function getUserAuthorities() {
  return ${userAuthorities};
}


function getIamVersion() {
  return '${iamVersion}';
}

function getIamGitCommitId() {
  return '${gitCommitId}';
}

function getRegistrationEnabled() {
  return ${loginPageConfiguration.registrationEnabled};
}

function getAccountLinkingEnabled() {
    return ${loginPageConfiguration.accountLinkingEnabled};
}

function getOrganisationName() {
 return '${iamOrganisationName}'; 
}

function getAccessTokenValiditySeconds() {
  return ${clientDefaultsProperties.defaultAccessTokenValiditySeconds};
}

function getRefreshTokenValiditySeconds() {
  return ${clientDefaultsProperties.defaultRefreshTokenValiditySeconds};
}

function getOidcEnabled() {
  return ${loginPageConfiguration.oidcEnabled};
}
	
function getSamlEnabled() {
  return ${loginPageConfiguration.samlEnabled};
}

function getRcauthEnabled() {
  return ${iamRcauthEnabled};
}

function getExternalAuthenticationEnabled() {
    return ${loginPageConfiguration.externalAuthenticationEnabled};
}
</script>
