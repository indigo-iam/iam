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

    function ClientSettingsController() {
        var self = this;

        self.$onInit = function () {
            console.debug('ClientSettingsController.self', self);
        };
    }

    angular
        .module('dashboardApp')
        .component('clientsettings', clientsettings());


    function clientsettings() {

        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/clientsettings/clientsettings.component.html",
            bindings: {
                client: '=',
                newClient: '='
            },
            controller: ClientSettingsController,
            controllerAs: '$ctrl'
        }
    }

}());