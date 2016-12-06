<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<t:page title="Registration request verification">
  <c:choose>
    <c:when test="${verificationSuccess}">
      <h1 class="text-center">Request confirmed successfully</h1>
    </c:when>
    <c:otherwise>
      <h1 class="text-center">Request confirmation failure</h1>
    </c:otherwise>
  </c:choose>
  <div id="register-confirm-message">
    <c:choose>
      <c:when test="${verificationSuccess}">
        <p>Your registration request has been confirmed successfully, and is now waiting for administrator approval.
          As soon as your request is approved you will receive a confirmation email.</p>
      </c:when>
      <c:otherwise>
        <p>Something went wrong with your request.</p>
        <p>Detailed error message:</p>
        <p>${verificationMessage}</p>
      </c:otherwise>
    </c:choose>
    <div id="register-confirm-back-btn" class="row text-center">
      <a class="btn btn-primary" href='/login'>Back to Login Page</a>
    </div>
  </div>
</t:page>