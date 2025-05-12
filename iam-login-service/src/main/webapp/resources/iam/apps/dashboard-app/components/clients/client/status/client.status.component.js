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

  function ClientStatusController(toaster, ModalService, ClientsService) {
    var self = this;

    self.$onInit = function () {
      self.enabled = true;
    };

    self.handleError = function (error) {
      console.error(error);
      self.enabled = true;
    };

    self.handleSuccess = function () {
      self.enabled = true;
      ClientsService.retrieveClient(self.client.client_id).then(function (client) {
        console.debug("Loaded client", client);
        self.client = client;
        self.clientVal = angular.copy(self.client);
        if (client.active) {
          toaster.pop({
            type: 'success',
            body:
              `Client '${client.client_name}' has been restored successfully.`
          });
        } else {
          toaster.pop({
            type: 'success',
            body: `Client '${client.client_name}' is now disabled.`
          });
        }
      }).catch(function (res) {
        console.debug("Error retrieving client!", res);
        toaster.pop({
          type: 'error',
          body: 'Error retrieving client!'
        });
      });
    };

    self.handleSuccessRevoke = function () {
      self.enabled = true;
      ClientsService.retrieveClient(self.client.client_id).then(function (client) {
        console.debug("Loaded client", client);
        self.client = client;
        self.clientVal = angular.copy(self.client);
        toaster.pop({
            type: 'success',
            body:
              `Client '${client.client_name}''s refresh tokens have been successfully removed.`
          });
      }).catch(function (res) {
        console.debug("Error removing tokens!", res);
        toaster.pop({
          type: 'error',
          body: 'Error removing tokens!'
        });
      });
    };

    self.enableClient = function () {
      return ClientsService.enableClient(self.client.client_id)
        .then(self.handleSuccess)
        .catch(self.handleError);
    };

    self.disableClient = function () {
      return ClientsService.disableClient(self.client.client_id)
        .then(self.handleSuccess)
        .catch(self.handleError);
    };

    self.removeTokens = function () {
      return ClientsService.removeTokens(self.client.client_id)
        .then(self.handleSuccessRevoke)
        .catch(self.handleError);
    };

    self.tokenRemoval = function () {
      var updateStatusFunc = null;
      var refreshOptions = null;

      refreshOptions = {
        closeButtonText: 'Cancel',
        actionButtonText: 'Remove tokens',
        headerText: 'Remove ' + self.client.client_name + ' tokens',
        bodyText:
          `Are you sure you want to remove all tokens from client '${self.client.client_name}'?`
      };
      updateStatusFunc = self.removeTokens;

      ModalService.showModal({}, refreshOptions)
        .then(function () { updateStatusFunc(); })
        .catch(function () {
          console.debug("Error removing client tokens!", res);
        });

    }

    self.openDialog = function () {

      var modalOptions = null;
      var updateStatusFunc = null;
      var refreshOptions = null;

      if (self.client.active) {
        modalOptions = {
          closeButtonText: 'Cancel',
          actionButtonText: 'Disable client',
          headerText: 'Disable ' + self.client.client_name,
          bodyText:
            `Are you sure you want to disable client '${self.client.client_name}'?`
        };
        updateStatusFunc = self.disableClient;

      } else {
        modalOptions = {
          closeButtonText: 'Cancel',
          actionButtonText: 'Restore client',
          headerText: 'Restore ' + self.client.client_name,
          bodyText:
            `Are you sure you want to restore client '${self.client.client_name}'?`
        };
        updateStatusFunc = self.enableClient;
      }

      self.enable = false;
      ModalService.showModal({}, modalOptions)
        .then(function () { updateStatusFunc(); })
        .catch(function () {
          console.debug("Error updating client status!", res);
        });
    };
  }

  angular.module('dashboardApp').component('clientStatus', {
    require: { clientCtrl: '^client' },
    bindings: { client: '=' },
    templateUrl:
      '/resources/iam/apps/dashboard-app/components/clients/client/status/client.status.component.html',
    controller: [
      'toaster', 'ModalService', 'ClientsService', ClientStatusController
    ]
  });

})();