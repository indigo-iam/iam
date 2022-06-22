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
(function () {
    'use strict';

    angular
        .module('dashboardApp')
        .component('groupMembershipAdder', groupMembershipAdder());

    function GroupMembershipAdderController(toaster, $q, FindService, scimFactory) {
        var self = this;
        self.selectedGroups = [];

        self.searchResults = [];

        function handleSuccess(res) {
            self.close({ $value: 'Groups added succesfully!' });
        }

        function handleError(err) {
            var msg;

            if (err.data && err.data.error) {
                msg = err.data.error;
            } else {
                msg = err.statusText;
            }

            if (!msg) {
                self.error = "An error occurred. Is your network down?";
            } else {
                self.error = msg;
            }
        }

        self.clearError = function () {
            self.error = undefined;
        };

        self.cancel = function () {
            self.dismiss({ $value: 'Add group canceled!' });
        };

        self.labelName = function (label) {
            if (label.prefix) {
                return label.prefix + "/" + label.name;
            }

            return label.name;
        };

        function groupRank(g) {
            return (g.displayName.match(/\//g) || []).length;
        }

        // Returns true if g1 is parent of g2
        function isAncestor(g1, g2) {
            return g1.id !== g2.id && groupRank(g1) != groupRank(g2) &&
                g2.displayName.startsWith(g1.displayName);
        }
        self.submit = function () {

            var promises = [];
            var filteredGroups = [...self.selectedGroups];

            filteredGroups = filteredGroups.filter(function (g1) {
                for (let g2 of self.selectedGroups) {
                    if (isAncestor(g1, g2)) {
                        return false;
                    }
                }
                return true;
            });

            filteredGroups.slice().reverse().forEach(function (group) {
                promises.push(scimFactory.addUserToGroup(group.id, self.resolve.user));
            });

            return $q.all(promises).then(handleSuccess).catch(handleError);
        };

        self.findUnsubscribedGroups = function (search) {
            if (search === '' || search.length < 2) {
                search = undefined;
            }

            FindService.findUnsubscribedGroupsForAccount(self.resolve.user.id, search, 1).then(
                function (res) {
                    self.searchResults = res.Resources;
                });
        };

        self.$onInit = function () {
            console.log('GroupMembershipAdderController onInit');

            FindService.findUnsubscribedGroupsForAccount(self.resolve.user.id, null, 1).then(
                function (res) {
                    self.searchResults = res.Resources;
                });
        };
    }

    function groupMembershipAdder() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/group-membership/adder/group-membership.adder.component.html",
            bindings: {
                resolve: "<",
                close: "&",
                dismiss: "&"
            },
            controller: ['toaster', '$q', 'FindService', 'scimFactory',
                GroupMembershipAdderController
            ],
            controllerAs: '$ctrl'
        };
    }

}());