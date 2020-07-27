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
angular.module('dashboardApp').value('getUserInfo', getUserInfo);

angular
    .module('dashboardApp')
    .config(
        function ($stateProvider, $urlRouterProvider, $httpProvider) {



            $httpProvider.interceptors.push('gatewayErrorInterceptor');
            $httpProvider.interceptors.push('sessionExpiredInterceptor');

            $urlRouterProvider.otherwise(function ($injector, $location) {
                return '/home';
            });

            $stateProvider
                .state('home', {
                    url: '/home',
                    resolve: {
                        user: loadLoggedUser,
                        aup: loadAup,
                        labels: loadAccountLabelsAuthUser
                    },
                    views: {
                        content: {
                            component: 'user'
                        }
                    }
                })
                .state('user', {
                    url: '/user/:id',
                    resolve: {
                        user: loadUser,
                        aup: loadAup,
                        labels: loadAccountLabels
                    },
                    views: {
                        content: {
                            component: 'user'
                        }
                    }
                })
                .state(
                    'group', {
                        url: '/group/:id',
                        resolve: {
                            group: loadGroup,
                            labels: loadGroupLabels
                        },
                        views: {
                            content: {
                                component: 'group'
                            }
                        }
                    })
                .state(
                    'users', {
                        url: '/users',
                        views: {
                            content: {
                                component: 'users'
                            }
                        }
                    })
                .state(
                    'groups', {
                        url: '/groups',
                        views: {
                            content: {
                                component: 'groups'
                            }
                        }
                    })
                .state(
                    'scopes', {
                        url: '/scopes',
                        resolve: {
                            scopes: loadScopes
                        },
                        views: {
                            content: {
                                component: 'scopes'
                            }
                        }
                    })
                .state(
                    'requests', {
                        url: '/requests',
                        views: {
                            content: {
                                component: 'requests'
                            }
                        }
                    })
                .state(
                    'tokens', {
                        url: '/tokens',
                        views: {
                            content: {
                                component: 'tokens'
                            }
                        }
                    })
                .state('aup', {
                    url: '/aup',
                    resolve: {
                        aup: loadAup
                    },
                    views: {
                        content: {
                            component: 'aup'
                        }
                    }
                });

            function loadLoggedUser(UserService) {
                return UserService.getMe();
            }

            function loadUser(UserService, $stateParams) {
                return UserService.getUser($stateParams.id);
            }

            function loadGroup(GroupService, $stateParams) {
                return GroupService.getGroup($stateParams.id);

            }
            
            function loadAup(AupService) {
                return AupService.getAup();
            }

            function loadScopes(ScopesService) {
                return ScopesService.getAllScopes();

            }

            function loadGroupLabels(LabelsService, $stateParams) {
                return LabelsService.getGroupLabels($stateParams.id);
            }

            function loadAccountLabels(LabelsService, $stateParams) {
                return LabelsService.getAccountLabels($stateParams.id);
            }

            function loadAccountLabelsAuthUser(LabelsService) {
                return LabelsService.getAccountLabelsForAuthenticatedUser();
            }
        });