<%@attribute name="title" required="false"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ tag import="com.google.gson.Gson" %>
<!DOCTYPE html>
<html lang="${pageContext.response.locale}">
<head>

    <base href="${config.issuer}">

    <meta charset="utf-8">
    <title>${config.topbarTitle} - ${title}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="">
    <meta name="author" content="">

    <!-- stylesheets -->
    <link href="${resourcesPrefix}/bootstrap2/css/bootstrap.css" rel="stylesheet">
    <link href="${resourcesPrefix}/css/bootstrap-sheet.css" rel="stylesheet">
    <link href="${resourcesPrefix}/css/mitreid-connect.css" rel="stylesheet">
    <link href="${resourcesPrefix}/css/mitreid-connect-local.css" rel="stylesheet">
    <link href="${resourcesPrefix}/bootstrap2/css/bootstrap-responsive.css" rel="stylesheet">
    <link href="${resourcesPrefix}/css/mitreid-connect-responsive.css" rel="stylesheet">
    <link href="${resourcesPrefix}/css/mitreid-connect-responsive-local.css" rel="stylesheet">

    <!-- HTML5 shim, for IE6-8 support of HTML5 elements -->
    <!--[if lt IE 9]>
    <script src="${resourcesPrefix}/js/lib/html5.js"></script>
    <![endif]-->

    <!-- favico -->
    <link rel="shortcut icon" href="${resourcesPrefix}/images/mitreid-connect.ico">

    <!-- Load jQuery up here so that we can use in-page functions -->
    <script type="text/javascript" src="${resourcesPrefix}/js/lib/jquery.js"></script>
    <c:if test="${not empty _csrf}">
        <meta name="_csrf" content="<c:out value='${_csrf.token}'/>">
        <meta name="_csrf_header" content="<c:out value='${_csrf.headerName}'/>">
    </c:if>
    <script type="text/javascript">
        $.ajaxPrefilter(function(options) {
            var method = (options.type || 'GET').toUpperCase();
            if (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method)) {
                return;
            }
            var resolved = new URL(options.url, document.baseURI);
            if (resolved.origin !== window.location.origin) {
                return;
            }
            var token = document.querySelector('meta[name="_csrf"]');
            var header = document.querySelector('meta[name="_csrf_header"]');
            if (token && token.content && header && header.content) {
                options.headers = options.headers || {};
                if (!options.headers[header.content]) {
                    options.headers[header.content] = token.content;
                }
            }
        });
    </script>
    <script type="text/javascript" charset="UTF-8" src="${resourcesPrefix}/js/lib/moment-with-locales.js"></script>
    <script type="text/javascript" src="${resourcesPrefix}/js/lib/i18next.js"></script>
    <script type="text/javascript">
        $.i18n.init({
            fallbackLng: "en",
            lng: "${config.locale}",
            resGetPath: "resources/js/locale/__lng__/__ns__.json",
            ns: {
            	namespaces: ${config.languageNamespacesString},
            	defaultNs: '${config.defaultLanguageNamespace}'
            },
            fallbackNS: ${config.languageNamespacesString}
        });
        moment.locale("${config.locale}");
    	// safely set the title of the application
    	function setPageTitle(title) {
    		document.title = "${config.topbarTitle} - " + title;
    	}
    	
		// get the info of the current user, if available (null otherwise)
    	function getUserInfo() {
    		return ${userInfoJson};
    	}
		
		// get the authorities of the current user, if available (null otherwise)
		function getUserAuthorities() {
			return ${userAuthorities};
		}
		
		// is the current user an admin?
		// NOTE: this is just for  
		function isAdmin() {
			var auth = getUserAuthorities();
			if (auth && _.contains(auth, "ROLE_ADMIN")) {
				return true;
			} else {
				return false;
			}
		}
		
		var heartMode = ${config.heartMode};
		
    </script>    
</head>

<body>

<div id="wrap">

<!-- Start body -->