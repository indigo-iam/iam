/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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

(function () {
    'use strict';

    angular.module('dashboardApp', [
        'ui.router', 'ui.bootstrap', 'ui.bootstrap.tpls', 'ui.select', 'ngCookies',
        'ngSanitize', 'relativeDate', 'ngResource', 'toaster'
    ]);


    angular.module('dashboardApp')
        .run(function (
            $window, $rootScope, $state, $stateParams, $q, $uibModal, $trace, Utils,
            UserService, RegistrationRequestService, TokensService, GroupRequestsService, ScopesService, toaster) {

            $state.defaultErrorHandler(function (response) {
                if (response.status) {
                    console.error(response.status, response.statusText);
                    toaster.pop({
                        type: 'error',
                        body: response.statusText
                    });
                } else {
                    console.error(response);
                    toaster.pop({
                        type: 'error',
                        body: 'An unexpected error occurred!'
                    });
                }
            });

            $rootScope.iamVersion = getIamVersion();
            $rootScope.iamCommitId = getIamGitCommitId();
            $rootScope.accountLinkingEnabled = getAccountLinkingEnabled();
            $rootScope.organisationName = getOrganisationName();

            $trace.enable('TRANSITION');

            // Offline dialog
            $rootScope.closeOfflineDialog = function () {

                console.log('into: closeOfflineDialog');

                if ($rootScope.offlineDialog) {
                    console.log('Closing offline dialog');
                    $rootScope.offlineDialog.dismiss('Back online');
                    $rootScope.offlineDialog = undefined;
                }
            };

            $rootScope.openOfflineDialog = function () {

                if (!$rootScope.offlineDialog) {
                    console.log('Opening offline dialog');
                    $rootScope.offlineDialog = $uibModal.open({
                        animation: false,
                        backdrop: 'static',
                        keyboard: false,
                        templateUrl: 'noConnectionTemplate.html'
                    });
                }
            };

            $rootScope.pendingRequests = {};

            $rootScope.reloadInfo = function () {

                var promises = [];
                promises.push(UserService.updateLoggedUserInfo());

                if ($rootScope.isRegistrationEnabled && Utils.isAdmin()) {
                    promises.push(RegistrationRequestService.listPending().then(function (r) {
                        $rootScope.pendingRegistrationRequests(r.data);
                    }));
                    promises.push(GroupRequestsService.getGroupRequests({
                        status: 'PENDING'
                    }).then(function (r) {
                        $rootScope.pendingGroupMembershipRequests(r);
                    }));
                    promises.push(TokensService.getAccessTokensCount().then(function (r) {
                        $rootScope.accessTokensCount = r.data.totalResults;
                    }));
                    promises.push(TokensService.getRefreshTokensCount().then(function (r) {
                        $rootScope.refreshTokensCount = r.data.totalResults;
                    }));
                    promises.push(ScopesService.getAllScopes().then(function (r) {
                        $rootScope.scopesCount = r.data.length;
                    }));
                }

                return $q.all(promises).catch(function (error) {
                    console.error("Error loading logged user info" + error);
                });
            };

            $rootScope.reloadInfo();

            // ctrl+R refresh
            $rootScope.reload = function () {
                $window.location.reload();
            };

            // refresh last state loaded
            $rootScope.refresh = function () {

                $rootScope.closeOfflineDialog();
                $state.transitionTo(
                    $state.current, $stateParams, {
                        reload: true,
                        inherit: false,
                        notify: true
                    });
            };

            $rootScope.pendingRegistrationRequests = function (val) {
                if (val) {
                    $rootScope.pendingRequests.reg = val;
                }
                return $rootScope.pendingRequests.reg;
            };

            $rootScope.pendingGroupMembershipRequests = function (val) {
                if (val) {
                    $rootScope.pendingRequests.gm = val;
                }
                return $rootScope.pendingRequests.gm;
            };

            $rootScope.pendingRequestsCount = function () {

                var groupRequestsCount = function () {
                    var grCount = 0;
                    if ($rootScope.pendingRequests.gm) {
                        grCount = $rootScope.pendingRequests.gm.totalResults;
                    }
                    return grCount;
                };

                if (Utils.isAdmin()) {
                    var rrCount = 0;
                    if ($rootScope.pendingRequests.reg) {
                        rrCount = $rootScope.pendingRequests.reg.length;
                    }

                    var grCount = groupRequestsCount();

                    return rrCount + grCount;

                } else if (Utils.isGroupManager()) {
                    return groupRequestsCount();
                }

                return 0;

            };

            $('#body').show();
        });
})();