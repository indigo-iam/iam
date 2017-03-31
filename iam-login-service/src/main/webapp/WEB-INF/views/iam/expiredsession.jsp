<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>

<o:iamHeader title="Session Expired" />

<body>

    <div class="absolute-center is-responsive">

        <div id="logo-container" style="background-image: url(${config.logoImageUrl})"></div>

        <div style="text-align: center;">
            <h3>Session Expired</h3>
        </div>

        <div style="font-size: medium;">
            <p class="text-center">Your session seems to be expired.</p>
        </div>
        
        <div class="row text-center">
            <a class="btn btn-primary" href='/login'>Back to Login Page</a>
        </div>

    </div>

</body>
