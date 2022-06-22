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

  function RemoveSamlIdController($uibModalInstance, scimFactory, user, samlId) {
    var self = this;

    self.error = undefined;
    self.user = user;
    self.samlId = samlId;
    self.enabled = true;


    self.cancel = function () {
      $uibModalInstance.dismiss("Cancel");
    };

    self.doRemove = function () {
      self.enabled = false;
      self.error = undefined;
      scimFactory.removeSamlId(self.user.id, self.samlId).then(function (response) {
        $uibModalInstance.close(`SAML account removed`);
        self.enabled = true;
      }).catch(function (error) {
        console.error(error);
        self.error = error;
        self.enabled = true;
      });
    };
  }

  function AddSamlIdController($uibModalInstance, scimFactory, user) {
    var self = this;

    self.error = undefined;
    self.user = user;

    self.reset = function () {
      self.samlId = {
        "idpId": "",
        "attributeId": "",
        "userId": ""
      };
      self.enabled = true;
    };

    self.reset();

    self.cancel = function () {
      $uibModalInstance.dismiss("Cancel");
    };

    self.doAdd = function () {
      self.error = undefined;
      self.enabled = false;
      scimFactory.addSamlId(self.user.id, self.samlId).then(function (response) {
        $uibModalInstance.close(`SAML account added`);
        self.enabled = true;
      }).catch(function (error) {
        console.error(error);
        self.error = error;
        self.enabled = true;
      });
    };
  }

  function LinkSamlController(AccountLinkingService, $uibModalInstance, action, account) {
    var self = this;

    self.enabled = true;
    self.showLinkButton=true;
    self.action = action;
    self.actionUrl = '/iam/account-linking/SAML';
    self.type = 'SAML';
    self.account = account;
    self.error = undefined;

    self.doLink = function() {
      self.enabled = false;
      document.getElementById("link-account-form").submit();
    };


    self.doUnlink = function () {
      self.enabled = false;
      self.error = undefined;

      AccountLinkingService.unlinkSamlAccount({
        iss: self.account.idpId,
        attr: self.account.attributeId,
        sub: self.account.userId
      }).then(function (response) {
        $uibModalInstance.close("SAML account unlinked");
      }).catch(function (error) {
        console.error(error);

        self.error = error;
        self.enabled = true;
      });
    };

    self.cancel = function () {
      $uibModalInstance.dismiss('Dismissed');
    };
  }

  function IdpSelectionController(
    $scope, $http, $uibModalInstance, $window, $timeout) {
    $scope.ok = function () {
      $window.location.href = '/saml/login?idp=' + $scope.idpSelected.entityId;
    };

    $scope.cancel = function () {
      $uibModalInstance.close();
    };

    $scope.reset = function () {
      $scope.idpSelected = null;
      $timeout(function () {
        $window.document.getElementById('idp-selection-input').focus();
      }, 0);
    };

    $scope.lookupIdp = function (val) {

      var result =
        $http.get('/saml/idps', {
          params: {
            q: val
          }
        }).then(function (response) {
          return response.data;
        });

      return result;
    };
  }

  function UserSamlController(toaster, $uibModal, ModalService, scimFactory) {
    var self = this;

    self.SAML_ATTRIBUTES = [{
      name: "eduPersonUniqueId",
      oid: "urn:oid:1.3.6.1.4.1.5923.1.1.1.13"
    }, {
      name: "eduPersonTargetedId",
      oid: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
    }, {
      name: "eduPersonPrincipalName",
      oid: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
    }, {
      name: "eduPersonOrcid",
      oid: "urn:oid:1.3.6.1.4.1.5923.1.1.1.16"
    }, {
      name: "employeeNumber",
      oid: "urn:oid:2.16.840.1.113730.3.1.3"
    }, {
      name: "spidCode",
      oid: "spidCode"
    }];

    self.SAML_NAME_TO_OID = {};
    self.SAML_OID_TO_NAME = {};

    for (let v in self.SAML_ATTRIBUTES) {
      self.SAML_NAME_TO_OID[v.name] = v.oid;
      self.SAML_OID_TO_NAME[v.oid] = v.name;
    }

    self.samlAttributeNameToOid = function (name) {
      return self.SAML_NAME_TO_OID[name];
    };

    self.samlAttributeOidToName = function (oid) {
      return self.SAML_OID_TO_NAME[oid];
    };

    self.indigoUser = function () {
      return self.user['urn:indigo-dc:scim:schemas:IndigoUser'];
    };

    self.$onInit = function () {
      console.log('UserSamlController onInit');
      self.enabled = true;
    };

    self.handleSuccess = function (msg) {
      self.enabled = true;
      self.userCtrl.loadUser().then(function () {
        toaster.pop({
          type: 'success',
          body: msg
        });
      });
    };

    self.openLinkSamlAccountDialog = function () {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/components/common/user.linking.dialog.html',
        controller: LinkSamlController,
        controllerAs: '$ctrl',
        resolve: {
          action: function () {
            return 'link';
          },
          account: undefined
        }
      });

      modalInstance.result.then(self.handleSuccess);

    };

    self.openAddSamlAccountDialog = function () {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/components/user/saml/saml-id.add.dialog.html',
        controller: AddSamlIdController,
        controllerAs: '$ctrl',
        resolve: {
          user: function () {
            return self.user;
          }
        }
      });

      modalInstance.result.then(self.handleSuccess);
    };

    self.openRemoveSamlAccountDialog = function (samlId) {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/components/user/saml/saml-id.remove.dialog.html',
        controller: RemoveSamlIdController,
        controllerAs: '$ctrl',
        resolve: {
          user: function () {
            return self.user;
          },
          samlId: samlId
        }
      });

      modalInstance.result.then(self.handleSuccess);
    };

    self.openUnlinkSamlAccountDialog = function (samlId) {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/components/user/saml/saml-id.unlink.dialog.html',
        controller: LinkSamlController,
        controllerAs: '$ctrl',
        resolve: {
          action: function () {
            return 'unlink';
          },
          account: samlId
        }
      });

      modalInstance.result.then(self.handleSuccess);

    };

    self.hasSamlIds = function () {
      var samlIds = self.getSamlIds();

      if (samlIds) {
        return samlIds.length > 0;
      }

      return false;
    };

    self.getSamlIds = function () {
      if (self.indigoUser()) {
        return self.indigoUser().samlIds;
      }

      return undefined;
    };
  }

  angular.module('dashboardApp').component('userSaml', {
    require: {
      userCtrl: '^user'
    },
    bindings: {
      user: '='
    },
    templateUrl: '/resources/iam/apps/dashboard-app/components/user/saml/user.saml.component.html',
    controller: [
      'toaster', '$uibModal', 'ModalService', 'scimFactory', UserSamlController
    ]
  });
})();
