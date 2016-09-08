<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>

<o:iamHeader title="Registration Request Verification" />

<body>

	<div class="absolute-center is-responsive">

		<div id="logo-container"></div>

		<c:if test="${verificationSuccess}">
			<div style="text-align: center;">
				<h3>Confirmation success</h3>
			</div>

			<div style="font-size: medium;">
				<p class="text-center">Your Indigo registration request has been confirmed successfully.</p>
				<p class="text-center">Now you have to wait for approval from Indigo Admin before start using Indigo services.</p>
			</div>
		</c:if>

		<c:if test="${verificationFailure}">
			<div style="text-align: center;">
				<h3>Confirmation failure</h3>
			</div>
			<div style="font-size: medium;">
				<p class="text-center">Your Indigo registration request fail.</p>
				<p class="text-center">Detailed error message:</p>
				<p class="text-center">${verificationMessage}</p>
			</div>
		</c:if>

		<div style="width: 200px; margin: auto;">
			<a class="btn btn-primary btn-block" style="align: center" href='/login'>Back to Login Page</a>
		</div>
			
	</div>

</body>
