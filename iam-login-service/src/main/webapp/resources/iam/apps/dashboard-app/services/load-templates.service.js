/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
(function() {
    'use strict';

    angular.module('dashboardApp')
        .factory('LoadTemplatesService', LoadTemplatesService);

    LoadTemplatesService.$inject = ['$http', '$templateCache', '$q'];

    // It's up to the developer to keep this list updated
    var TEMPLATES = [
        '/resources/iam/apps/dashboard-app/templates/common/userinfo-box.html',
        '/resources/iam/apps/dashboard-app/templates/header.html',
        '/resources/iam/apps/dashboard-app/templates/home/account-link-dialog.html',
        '/resources/iam/apps/dashboard-app/templates/home/editpassword.html',
        '/resources/iam/apps/dashboard-app/templates/home/edituser.html',
        '/resources/iam/apps/dashboard-app/templates/home/home.html',
        '/resources/iam/apps/dashboard-app/templates/loading-modal.html',
        '/resources/iam/apps/dashboard-app/templates/nav.html',
        '/resources/iam/apps/dashboard-app/templates/operation-result.html',
        '/resources/iam/apps/dashboard-app/templates/requests/management.html',
        '/resources/iam/apps/dashboard-app/templates/user/addsshkey.html',
        '/resources/iam/apps/dashboard-app/templates/user/addusergroup.html',
        '/resources/iam/apps/dashboard-app/templates/user/assign-vo-admin-privileges.html',
        '/resources/iam/apps/dashboard-app/templates/user/edituser.html',
        '/resources/iam/apps/dashboard-app/templates/user/revoke-vo-admin-privileges.html',
        '/resources/iam/apps/dashboard-app/templates/user/user.html',
        '/resources/iam/apps/dashboard-app/components/common/result.component.html',
        '/resources/iam/apps/dashboard-app/components/common/user.linking.dialog.html',
        '/resources/iam/apps/dashboard-app/components/user/detail/user.detail.component.html',
        '/resources/iam/apps/dashboard-app/components/user/edit/user.edit.component.html',
        '/resources/iam/apps/dashboard-app/components/user/groups/user.groups.component.html',
        '/resources/iam/apps/dashboard-app/components/user/password/user.password.component.html',
        '/resources/iam/apps/dashboard-app/components/user/privileges/user.privileges.component.html',
        '/resources/iam/apps/dashboard-app/components/user/saml/user.saml.component.html',
        '/resources/iam/apps/dashboard-app/components/user/status/user.status.component.html',
        '/resources/iam/apps/dashboard-app/components/user/user.component.html',
        '/resources/iam/apps/dashboard-app/components/users/users.component.html',
        '/resources/iam/apps/dashboard-app/components/users/userslist/users.userslist.component.html',
        '/resources/iam/apps/dashboard-app/components/users/userslist/user.add.dialog.html',
        '/resources/iam/apps/dashboard-app/components/users/userslist/user.delete.dialog.html',
        '/resources/iam/apps/dashboard-app/components/groups/groups.component.html',
        '/resources/iam/apps/dashboard-app/components/groups/groupslist/groups.groupslist.component.html',
        '/resources/iam/apps/dashboard-app/components/groups/groupslist/group.add.dialog.html',
        '/resources/iam/apps/dashboard-app/components/groups/groupslist/group.delete.dialog.html',
        '/resources/iam/apps/dashboard-app/components/groups/groupslist/subgroup.add.dialog.html',
        '/resources/iam/apps/dashboard-app/components/tokens/tokens.component.html',
        '/resources/iam/apps/dashboard-app/components/tokens/accesslist/token.revoke.dialog.html',
        '/resources/iam/apps/dashboard-app/components/tokens/accesslist/tokens.accesslist.component.html',
        '/resources/iam/apps/dashboard-app/components/tokens/refreshlist/token.revoke.dialog.html',
        '/resources/iam/apps/dashboard-app/components/tokens/refreshlist/tokens.refreshlist.component.html',
        '/resources/iam/apps/dashboard-app/components/aup/aup.component.html',
        '/resources/iam/apps/dashboard-app/components/aup/aup.create.dialog.html',
        '/resources/iam/apps/dashboard-app/components/aup/aup.delete.dialog.html',
        '/resources/iam/apps/dashboard-app/components/aup/aup.edit.dialog.html'
    ];

    function LoadTemplatesService($http, $templateCache, $q) {
        var service = { loadTemplates: loadTemplates };

        return service;

        function loadTemplates() {

            var promises = [];

            TEMPLATES.forEach(function(t) {
                promises.push($http.get(t, { cache: $templateCache }));
            });

            return $q.all(promises).then(function() {
                console.info("Templates loaded");
            }).catch(function(error) {
                console.error("Error loading template: " + error);
            });
        }
    }

})();