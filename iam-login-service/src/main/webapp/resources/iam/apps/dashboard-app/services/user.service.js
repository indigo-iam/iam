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
'use strict'

angular.module('dashboardApp').factory('UserService', UserService);

UserService.$inject = ['$q', '$rootScope', 'scimFactory', 'Authorities', 'Utils', 'AupService', 'UsersService', 'GroupsService', 'AuthenticatorAppService'];

function UserService($q, $rootScope, scimFactory, Authorities, Utils, AupService, UsersService, GroupsService, AuthenticatorAppService) {
    var service = {
        getUser: getUser,
        getMe: getMe,
        updateLoggedUserInfo: updateLoggedUserInfo
    };

    return service;

    function getMeAndAuthorities() {
        return scimFactory.getMe().then(function (r) {
            var user = r.data;
            user.authorities = getUserAuthorities();
            return user;
        });
    }

    function getMe() {
        return $q.all([getMeAndAuthorities(),
        AupService.getAupSignature(), AuthenticatorAppService.getMfaSettings()
        ]).then(
            function (result) {
                var user = result[0];
                if (result[1] !== null) {
                    user.aupSignature = result[1].data;
                    if (user.aupSignature.aup.signatureValidityInDays != 0){
                        user.aupSignatureExpiryDate = new Date(new Date(user.aupSignature.signatureTime).getTime() + 
                                                        user.aupSignature.aup.signatureValidityInDays * 24 * 60 * 60 * 1000);
                    }  
                } else {
                    user.aupSignature = null;
                }
                if (result[2] !== null) {
                    user.isMfaActive = result[2];
                }
                return user;
            }).catch(function (error) {
                console.error('Error loading authenticated user information: ', error);
                return $q.reject(error);
            });
    }

    function getUser(userId) {
        return $q
            .all([scimFactory.getUser(userId), Authorities.getAuthorities(userId), AupService.getAupSignatureForUser(userId),
                AuthenticatorAppService.getMfaSettingsForAccount(userId)
            ])
            .then(function (result) {
                var user = result[0].data;
                user.authorities = result[1].data.authorities;
                if (result[2] !== null) {
                    user.aupSignature = result[2].data;
                    if (user.aupSignature.aup.signatureValidityInDays != 0){
                        user.aupSignatureExpiryDate = new Date(new Date(user.aupSignature.signatureTime).getTime() + 
                                                        user.aupSignature.aup.signatureValidityInDays * 24 * 60 * 60 * 1000);
                    }
                } else {
                    user.aupSignature = null;
                }

                if (result[3] !== null) {
                    user.isMfaActive = result[3];
                }
                return user;
            })
            .catch(function (error) {
                console.error('Error loading user information: ', error);
                return $q.reject(error);
            });
    }

    function updateLoggedUserInfo() {

        $rootScope.isRegistrationEnabled = Utils.isRegistrationEnabled();
        $rootScope.isOidcEnabled = Utils.isOidcEnabled();
        $rootScope.isSamlEnabled = Utils.isSamlEnabled();

        var promises = [];

        promises.push(scimFactory.getMe().then(function (r) {
            $rootScope.loggedUser = Utils.getLoggedUser();
            $rootScope.loggedUser.me = r.data;
        }));

        if (Utils.isAdmin() || Utils.isReader()) {
            promises.push(
                UsersService.getUsersCount().then(function (r) {
                    $rootScope.usersCount = r.data.totalResults;
                }),
                GroupsService.getGroupsCount().then(function (r) {
                    $rootScope.groupsCount = r.data.totalResults;
                }));
        }

        return $q.all(promises)
            .then(function (data) {
                console.debug('Logged user info loaded succesfully');
            })
            .catch(function (error) {
                console.error('Error loading logged user info ' + error);
            });
    }
}