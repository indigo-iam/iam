<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>

<o:iamHeader title="Registration Request Submitted" />

<body>

	<div class="absolute-center is-responsive">

		<div id="logo-container"></div>

		<div style="text-align: center;">
			<h3>Request submission success</h3>
		</div>

		<div style="font-size: medium;">
			<p class="text-center">Your Indigo registration request has been submitted successfully.</p>
			<p class="text-center">Now, an email with a confirmation link will be sent to the email address specified in the request.
			   Check you mailbox!</p>
			<p class="text-center">After confirmation, you have to wait for approval from Indigo Admin before start using Indigo services.</p>
		</div>
		
		<div class="row col-sm-12 text-center">
			<a class="btn btn-primary" href='/login'>Back to Login Page</a>
		</div>

	</div>

</body>
