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

    angular.module('dashboardApp').factory("Utils", Utils);

    Utils.$inject = [];

    function Utils() {

        var service = {
            s4: s4,
            uuid: uuid,
            isMe: isMe,
            isAdmin: isAdmin,
            isUser: isUser,
            getLoggedUser: getLoggedUser,
            isRegistrationEnabled: isRegistrationEnabled,
            isOidcEnabled: isOidcEnabled,
            isSamlEnabled: isSamlEnabled,
            buildErrorOperationResult: buildErrorOperationResult,
            buildSuccessOperationResult: buildSuccessOperationResult,
            buildErrorResult: buildErrorResult,
            userIsVoAdmin: userIsVoAdmin,
            isGroupManagerForGroup: isGroupManagerForGroup,
            isGroupManager: isGroupManager,
            isGroupMember: isGroupMember,
            username: username
        };

        return service;

        function s4() {
            return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
        }

        function uuid() {
            return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() +
                s4() + s4();
        }

        function username() {
            return getUserInfo().preferred_username;
        }

        function isMe(id) {

            return (id == getUserInfo().sub);
        }

        function userIsVoAdmin(user) {
            if (user.authorities) {
                if (user.authorities.indexOf('ROLE_ADMIN') > -1) {
                    return true;
                }
            }
            return false;
        }

        function isGroupMember(group) {
            return (getUserInfo().groups.indexOf(group.displayName) != -1);
        }

        function isAdmin() {

            return (getUserAuthorities().indexOf("ROLE_ADMIN") != -1);
        }

        function isUser() {

            return (getUserAuthorities().indexOf("ROLE_USER") != -1);
        }

        function isGroupManager() {
            const hasGmAuth = getUserAuthorities().filter((c) => c.startsWith('ROLE_GM:'));

            return hasGmAuth.length > 0;
        }

        function isGroupManagerForGroup(groupId) {
            return (getUserAuthorities().indexOf("ROLE_GM:" + groupId) != -1);
        }

        function getLoggedUser() {
            return { info: getUserInfo(), auth: getUserAuthorities(), isAdmin: isAdmin(), isGroupManager: isGroupManager(), isGroupManagerForGroup: isGroupManagerForGroup() };
        }

        function isRegistrationEnabled() {

            return getRegistrationEnabled();
        }

        function isOidcEnabled() {

            return getOidcEnabled();
        }

        function isSamlEnabled() {

            return getSamlEnabled();
        }

        function buildErrorResult(errorString) {

            return {
                type: "error",
                text: errorString
            };
        }

        function buildErrorOperationResult(error) {

            return {
                type: "error",
                text: error.data.error_description || error.data.detail || error.data.message
            };
        }

        function buildSuccessOperationResult(message) {

            return {
                type: "success",
                text: message
            };
        }
    }
})();