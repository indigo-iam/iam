(function() {
  'use strict';

  angular.module('dashboardApp')
      .factory('LoadTemplatesService', LoadTemplatesService);

  LoadTemplatesService.$inject = ['$http', '$templateCache', '$q'];

  // It's up to the developer to keep this list updated
  var TEMPLATES = [
    '/resources/iam/template/dashboard/common/userinfo-box.html',
    '/resources/iam/template/dashboard/group/group.html',
    '/resources/iam/template/dashboard/groups/groups.html',
    '/resources/iam/template/dashboard/groups/newgroup.html',
    '/resources/iam/template/dashboard/header.html',
    '/resources/iam/template/dashboard/home/account-link-dialog.html',
    '/resources/iam/template/dashboard/home/editpassword.html',
    '/resources/iam/template/dashboard/home/edituser.html',
    '/resources/iam/template/dashboard/home/home.html',
    '/resources/iam/template/dashboard/loading-modal.html',
    '/resources/iam/template/dashboard/nav.html',
    '/resources/iam/template/dashboard/operation-result.html',
    '/resources/iam/template/dashboard/requests/management.html',
    '/resources/iam/template/dashboard/user/addoidc.html',
    '/resources/iam/template/dashboard/user/addsamlaccount.html',
    '/resources/iam/template/dashboard/user/addsshkey.html',
    '/resources/iam/template/dashboard/user/addusergroup.html',
    '/resources/iam/template/dashboard/user/addx509certificate.html',
    '/resources/iam/template/dashboard/user/assign-vo-admin-privileges.html',
    '/resources/iam/template/dashboard/user/edituser.html',
    '/resources/iam/template/dashboard/user/revoke-vo-admin-privileges.html',
    '/resources/iam/template/dashboard/user/user.html',
    '/resources/iam/template/dashboard/users/newuser.html',
    '/resources/iam/template/dashboard/users/users.html',
    '/resources/iam/js/dashboard-app/components/common/result.component.html',
    '/resources/iam/js/dashboard-app/components/user/detail/user.detail.component.html',
    '/resources/iam/js/dashboard-app/components/user/edit/user.edit.component.html',
    '/resources/iam/js/dashboard-app/components/user/groups/user.groups.component.html',
    '/resources/iam/js/dashboard-app/components/user/oidc/user.oidc.component.html',
    '/resources/iam/js/dashboard-app/components/user/password/user.password.component.html',
    '/resources/iam/js/dashboard-app/components/user/privileges/user.privileges.component.html',
    '/resources/iam/js/dashboard-app/components/user/saml/user.saml.component.html',
    '/resources/iam/js/dashboard-app/components/user/status/user.status.component.html',
    '/resources/iam/js/dashboard-app/components/user/user.component.html'
  ];

  function LoadTemplatesService($http, $templateCache, $q) {
    var service = {loadTemplates: loadTemplates};
    
    return service;

    function loadTemplates() {

        var promises = [];
        
        TEMPLATES.forEach(function(t){
            promises.push($http.get(t, {cache:$templateCache}));
        });

        return $q.all(promises).then(function(){
            console.info("Templates loaded");
        }).catch(function(error){
            console.error("Error loading template: "+error);
        });
    }
  }

})();