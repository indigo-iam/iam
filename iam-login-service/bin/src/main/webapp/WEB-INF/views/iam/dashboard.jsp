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
<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<o:iamHeader title="INDIGO IAM | Dashboard" />
<body id="body" class="skin-blue" ng-app="dashboardApp" ng-cloak style="display: none">
  <script type="text/ng-template" id="noConnectionTemplate.html">
                            <div class="modal-header">
                                <h3 class="modal-title">Lost connection to the IAM server</h3>
                                /div>
                                <div class="modal-body">
                                    <p>The connection was interrupted while the page was loading.</p>
                                    <ul>
                                        <li>The site could be temporarily unavailable or too busy. Try again in a few moments.</li>
                                    </ul>
                                </div>

                                <div class="modal-footer" class="text-center">
                                    <button class="btn btn-primary" data-dismiss="modal" type="button" data-ng-click="$root.refresh()">Retry</button>
                                </div>
                        </script>
  <div class="wrapper">
    <toaster-container
      toaster-options="{'close-button': true, 'time-out':{ 'toast-error': 5000, 'toast-success': 5000, 'toast-warning': 5000 }, 'position-class': 'toast-top-center'}">
    </toaster-container>
    <header class="main-header" ng-cloak></header>
    <aside class="main-sidebar" ng-cloak>
      <sidebar />
    </aside>
    <!-- Content Wrapper. Contains page content -->
    <div class="content-wrapper" ng-cloak>
      <div id="iam-content" ui-view="content" ng-cloak></div>
    </div>
    <!-- /.content-wrapper -->
  </div>
  <!-- Libraries -->
  <script type="text/javascript" src="<c:url value='/webjars/jquery/jquery.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angularjs/angular.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-animate.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-resource.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-cookies.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angular-ui-router/angular-ui-router.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angular-ui-select/select.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angular-sanitize/angular-sanitize.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js'/>"></script>
  <script type="text/javascript" src="<c:url value='/webjars/bootstrap/bootstrap.min.js'/>"></script>
  <script type="text/javascript" src="/resources/iam/js/adminLTE.js"></script>
  <script type="text/javascript" src="/resources/iam/js/toaster/toaster.min.js"></script>
  <script type="text/javascript" src="/resources/iam/js/directive/angular-relative-date.min.js"></script>
  
  
  <!-- Dashboard app -->
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/dashboard-app.module.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/dashboard-app.config.js"></script>

  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/directives/registration.directive.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/directives/operation-result.directive.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/directives/isimage.directive.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/factory/gatewayerror.interceptor.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/factory/sessionexpired.interceptor.js"></script>
  
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/filters/start-from.filter.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/scim-factory.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/modal.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/passwordreset.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/registration.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/utils.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/authorities.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/user.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/load-templates.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/account-linking.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/tokens.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/clients.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/clipboard.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/aup.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/account-group-manager.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/users.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/groups.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/group.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/group-requests.service.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/services/labels.service.js"></script>
  
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/controllers/registration.controller.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/controllers/account-privileges.controller.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/controllers/edit-user.controller.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/controllers/add-user-group.controller.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/controllers/edit-password.controller.js"></script>
  

  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/header/header.directive.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/common/result.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/sidebar/sidebar.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/requests/requests.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/requests/registration/requests.registration.component.js"></script>
   <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/requests/group/requests.group.component.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/group-requests/join-group.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/group-requests/pending-requests.component.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/detail/user.detail.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/edit/user.edit.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/status/user.status.component.js"></script>
  <script type="text/javascript"
    src="/resources/iam/apps/dashboard-app/components/user/privileges/user.privileges.component.js"></script>
  <script type="text/javascript"
    src="/resources/iam/apps/dashboard-app/components/user/password/user.password.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/groups/user.groups.component.js"></script>
  <script type="text/javascript"
    src="/resources/iam/apps/dashboard-app/components/user/linked-accounts/user.linked-accounts.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/x509/user.x509.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/labels/user.labels.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/user/user.component.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/users/userslist/users.userslist.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/users/users.component.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/groups/search/groups.search.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/groups/groupslist/groups.groupslist.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/groups/groups.component.js"></script>
  
  <script type="text/javascript"
    src="/resources/iam/apps/dashboard-app/components/tokens/refreshlist/tokens.refreshlist.component.js"></script>
  <script type="text/javascript"
    src="/resources/iam/apps/dashboard-app/components/tokens/accesslist/tokens.accesslist.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/tokens/tokens.component.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/aup/aup.component.js"></script>
  
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/group/group.description.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/group/group.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/group/subgroups/group.subgroups.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/group/members/group.members.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/group/managers/group.managers.component.js"></script>
  <script type="text/javascript" src="/resources/iam/apps/dashboard-app/components/group/labels/group.labels.component.js"></script>

</body>
