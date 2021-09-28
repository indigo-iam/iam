<%--

    Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

--%>
<%@ page language="java" contentType="text/html; charset=utf-8"
	pageEncoding="utf-8"%>
<%@ page
	import="org.springframework.security.core.AuthenticationException"%>
<%@ page
	import="org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException"%>
<%@ page import="org.springframework.security.web.WebAttributes"%>
<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<spring:message code="approve.title" var="title" />
<o:header title="${title}" />

<!-- IAM client consent page -->

<div class="container main">
	<%
	if (session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) != null && !(session
			.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) instanceof UnapprovedClientAuthenticationException)) {
	%>
	<div class="alert-message error">
		<a href="#" class="close">&times;</a>

		<p>
			<strong><spring:message code="approve.error.not_granted" /></strong>
			(<%=((AuthenticationException) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)).getMessage()%>)
		</p>
	</div>
	<%
	}
	%>
	<c:remove scope="session" var="SPRING_SECURITY_LAST_EXCEPTION" />

	<t:page title="Approve">

		<div style="text-align: center">
			<h2 style="font-size: 25px">
				<spring:message code="approve.required_for" />
				<c:choose>
					<c:when test="${empty client.clientName}">
						<em><c:out value="${client.clientId}" /></em>
					</c:when>
					<c:otherwise>
						<em><c:out value="${client.clientName}" /></em>
					</c:otherwise>
				</c:choose>
			</h2>
			<c:if test="${ not empty client.logoUri }">
				<img src="api/clients/${ client.id }/logo"  width="60" height="60"/>
			</c:if>

			<form name="confirmationForm"
				action="${pageContext.request.contextPath.endsWith('/') ? pageContext.request.contextPath : pageContext.request.contextPath.concat('/') }authorize"
				method="post">&nbsp;
				<div class=row>
					<div class="span4">
						<legend style="margin-bottom: 0;">
							<spring:message code="approve.access_to" />
							:
						</legend>

						<c:if test="${ empty client.scope }">
							<div class="alert alert-block alert-error">
								<h4>
									<i class="icon-info-sign"></i>
									<spring:message code="approve.warning" />
									:
								</h4>
								<p>
									<spring:message code="approve.no_scopes" />
								</p>
							</div>
						</c:if>

						<c:forEach var="scope" items="${ scopes }">

							<label for="scope_${ fn:escapeXml(scope.value) }"
								class="checkbox"> <input type="checkbox"
								name="scope_${ fn:escapeXml(scope.value) }"
								id="scope_${ fn:escapeXml(scope.value) }"
								value="${ fn:escapeXml(scope.value) }" checked="checked">
								<c:if test="${ not empty scope.icon }">
									<i class="icon-${ fn:escapeXml(scope.icon) }"></i>
								</c:if> <c:choose>
									<c:when test="${ not empty scope.description }">
										<c:out value="${ scope.description }" />
									</c:when>
									<c:otherwise>
										<c:out value="${ scope.value }" />
									</c:otherwise>
								</c:choose> <c:if test="${ not empty claims[scope.value] }">
									<span class="claim-tooltip" data-toggle="popover"
										data-html="true" data-placement="right" data-trigger="hover"
										data-title="These values will be sent:"
										data-content="<div style=&quot;text-align: left;&quot;>
										<ul>
											<c:forEach var="claim" items="${ claims[scope.value] }">
												<li><b><c:out value="${ claim.key }" /></b>: <c:out
														value="${ claim.value }" /></li>
											</c:forEach>
										</ul>
					</div>
					" > <i class="icon-question-sign"></i> </span>
					</c:if>

					</label>

					</c:forEach>

					&nbsp;

					<legend style="margin-bottom: 0;">
						<spring:message code="approve.remember.title" />
						:
					</legend>
					<label for="remember-forever" class="radio"> <input
						type="radio" name="remember" id="remember-forever"
						value="until-revoked" ${ !consent ? 'checked="checked"' : '' }>
						<spring:message code="approve.remember.until_revoke" />
					</label> <label for="remember-hour" class="radio"> <input
						type="radio" name="remember" id="remember-hour" value="one-hour">
						<spring:message code="approve.remember.one_hour" />
					</label> <label for="remember-not" class="radio"> <input
						type="radio" name="remember" id="remember-not" value="none"
						${ consent ? 'checked="checked"' : '' }> <spring:message
							code="approve.remember.next_time" />
					</label>
				</div>
				&nbsp;
				<div>
					<c:choose>
						<c:when test="${ empty client.redirectUris }">
							<div class="alert alert-block alert-error">
								<h4>
									<i class="icon-info-sign"></i>
									<spring:message code="approve.warning" />
									:
								</h4>
								<spring:message code="approve.no_redirect_uri" />
								<spring:message code="Authorizing will redirect to" />
								<b><p>${ fn:escapeXml(redirect_uri) }</p></b>
							</div>
						</c:when>
						<c:otherwise>
							<spring:message code="Authorizing will redirect to" />
							<b><p>${ fn:escapeXml(redirect_uri) }</p></b>
						</c:otherwise>
					</c:choose>
				</div>
				&nbsp;
				<div class="row">
					<spring:message code="approve.label.authorize"
						var="authorize_label" />
					<spring:message code="approve.label.deny" var="deny_label" />
					<input id="user_oauth_approval" name="user_oauth_approval"
						value="true" type="hidden" /> <input type="hidden"
						name="${_csrf.parameterName}" value="${_csrf.token}" /> <input
						name="authorize" value="${authorize_label}" type="submit"
						onclick="$('#user_oauth_approval').attr('value',true)"
						class="btn btn-success btn-large" /> &nbsp; <input name="deny"
						value="${deny_label}" type="submit"
						onclick="$('#user_oauth_approval').attr('value',false)"
						class="btn btn-secondary btn-large" />
				</div>
			</form>
		</div>

		<script type="text/javascript">
		<!--
			$(document)
					.ready(
							function() {
								$('.claim-tooltip').popover();
								$('.claim-tooltip').on('click', function(e) {
									e.preventDefault();
									$(this).popover('show');
								});

								$(document)
										.on(
												'click',
												'#toggleMoreInformation',
												function(event) {
													event.preventDefault();
													if ($('#moreInformation')
															.is(':visible')) {
														// hide it
														$(
																'.moreInformationContainer',
																this.el)
																.removeClass(
																		'alert')
																.removeClass(
																		'alert-info')
																.addClass(
																		'muted');
														$('#moreInformation')
																.hide('fast');
														$(
																'#toggleMoreInformation i')
																.attr('class',
																		'icon-chevron-right');
													} else {
														// show it
														$(
																'.moreInformationContainer',
																this.el)
																.addClass(
																		'alert')
																.addClass(
																		'alert-info')
																.removeClass(
																		'muted');
														$('#moreInformation')
																.show('fast');
														$(
																'#toggleMoreInformation i')
																.attr('class',
																		'icon-chevron-down');
													}
												});

								var creationDate = "<c:out value="${ client.createdAt }" />";
								var displayCreationDate = $
										.t('approve.dynamically-registered-unkown');
								var hoverCreationDate = "";
								if (creationDate != null
										&& moment(creationDate).isValid()) {
									creationDate = moment(creationDate);
									if (moment().diff(creationDate, 'months') < 6) {
										displayCreationDate = creationDate
												.fromNow();
									} else {
										displayCreationDate = "on "
												+ creationDate.format("LL");
									}
									hoverCreationDate = creationDate
											.format("LLL");
								}

								$('#registrationTime')
										.html(displayCreationDate);
								$('#registrationTime').attr('title',
										hoverCreationDate);

							});
		//-->
		</script>
	</t:page>