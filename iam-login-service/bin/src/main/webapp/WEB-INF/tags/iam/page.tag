<%@attribute
  name="title"
  required="false"%>

<%@attribute
  name="footer"
  fragment="true"%>

<%@ taglib
  prefix="c"
  uri="http://java.sun.com/jsp/jstl/core"%>

<!DOCTYPE html>
<html lang="${pageContext.response.locale}">

<head>

<base href="${config.issuer}">
<title>${config.topbarTitle}-${title}</title>

<meta charset="utf-8">
<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0">

<link
  rel="stylesheet"
  href="<c:url value='/webjars/bootstrap/css/bootstrap.min.css'/>"></link>

<link
  rel="stylesheet"
  href="<c:url value='/webjars/angular-ui-select/select.min.css'/>"></link>

<link
  rel="stylesheet"
  href="resources/iam/css/AdminLTE.css"></link>


<link
  rel="stylesheet"
  href="resources/iam/css/skins/skin-blue.css"></link>

<link
  rel="stylesheet"
  href="resources/iam/css/ionicons/ionicons.min.css"></link>

<link
  rel="stylesheet"
  href="/webjars/font-awesome/css/font-awesome.css"></link>

<link
  rel="stylesheet"
  href="resources/iam/css/toaster.min.css" />

<link
  rel="stylesheet"
  href="resources/iam/css/iam.css"></link>
  
  <style type="text/css">
    #logo-container {
       margin: auto;
        margin-top: 10px;
        width: ${loginPageConfiguration.logo.width}px;
        height: ${loginPageConfiguration.logo.height}px;
        background-size: ${loginPageConfiguration.logo.dimension}px;
        background-image: url('${loginPageConfiguration.logo.url}');
        background-repeat: no-repeat;
    }
  </style>

</head>

<script type="text/javascript">
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
</script>

<body>
  <div class="container">
    <div class="absolute-center">
      <div id="logo-container" style="background-image: url(${config.logoImageUrl})">
        <a href="/"></a>
      </div>
      <div class="container-fluid page-content">
        <jsp:doBody />
      </div>
    </div>
  </div>
  <jsp:invoke fragment="footer"/>
</body>

</html>
