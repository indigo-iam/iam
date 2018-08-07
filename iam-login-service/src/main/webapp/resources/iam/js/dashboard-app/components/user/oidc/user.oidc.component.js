/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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

  function RemoveOidcController($uibModalInstance, scimFactory, user, account) {
    var self = this;

    self.user = user;
    self.enabled = true;
    self.error = undefined;
    self.account = account;

    self.doRemove = function () {
      self.error = undefined;
      self.enabled = false;
      scimFactory.removeOpenIDAccount(self.user.id, self.account).then(function (response) {
        $uibModalInstance.close('OpenID Connect account removed');
        self.enabled = true;
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


  function AddOidcController($uibModalInstance, scimFactory, user) {
    var self = this;

    self.user = user;
    self.enabled = true;
    self.error = undefined;

    self.reset = function () {
      self.account = {
        "issuer": "",
        "subject": ""
      };
      self.enabled = true;
    };

    self.reset();

    self.doAdd = function () {
      self.error = undefined;
      self.enabled = false;
      scimFactory.addOpenIDAccount(self.user.id, self.account).then(function (response) {
        $uibModalInstance.close('OpenID Connect account added');
        self.enabled = true;
      }).catch(function (error) {
        console.error(error);
        self.error = error;
        self.enabled = true;
      });
    };

    self.cancel = function () {
      $uibModalInstance.dismiss('Dismissed');
    };

    self.reset = function () {
      self.account = {
        "issuer": "",
        "subject": ""
      };
      self.enabled = true;
    };
  }

  function LinkOidcController(AccountLinkingService, $uibModalInstance, action, account) {
    var self = this;

    self.action = action;
    self.actionUrl = '/iam/account-linking/OIDC';
    self.type = 'OpenID-Connect';
    self.account = account;
    self.enabled = true;
    self.showLinkButton=false;
    self.providers;
    
    self.loadOidcProviders = loadOidcProviders;
    self.linkOidcAccount = linkOidcAccount;

    self.doLink = function () {
      self.enabled = false;
      document.getElementById("link-account-form").submit();
    };

    self.doUnlink = function () {
      self.enabled = false;
      AccountLinkingService.unlinkOidcAccount(self.account).then(function (response) {
        $uibModalInstance.close("OIDC account unlinked");
      }).catch(function (error) {
        console.error(error);
      });
    };
    
    self.cancel = function () {
      $uibModalInstance.dismiss('Dismissed');
    };
    
    self.loadOidcProviders();
    
    function loadOidcProviders (){
    	AccountLinkingService.getOidcProviders().then(
    	  function(result){
    		self.providers = result.data;
    	  },
    	  function(error) {
			console.log(error);
		  });
    }
    
    function linkOidcAccount(issuerName){
    	var provider = findOidcProvider(issuerName);
    	var input = angular.element( document.querySelector( '#oidc-issuer' ) );
    	input.val(provider.issuer);
    	document.getElementById("oidc-link-account").submit();
    }
    
    function findOidcProvider(name){
    	return self.providers.find(item => {
    		return item.name == name;
    	})
    }
  }

  function UserOidcController($uibModal, toaster, ModalService, scimFactory) {
    var self = this;

    self.indigoUser = function () {
      return self.user['urn:indigo-dc:scim:schemas:IndigoUser'];
    };

    self.$onInit = function () {
      console.log('UserOidcController onInit');
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

    self.hasOidcIds = function () {
      var oidcIds = self.getOidcIds();

      if (oidcIds) {
        return oidcIds.length > 0;
      }

      return false;
    };

    self.getOidcIds = function () {
      if (self.indigoUser()) {
        return self.indigoUser().oidcIds;
      }

      return undefined;
    };

    self.openAddOidcAccountDialog = function () {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/js/dashboard-app/components/user/oidc/oidc-id.add.dialog.html',
        controller: AddOidcController,
        controllerAs: '$ctrl',
        resolve: {
          user: function () {
            return self.user;
          }
        }
      });

      modalInstance.result.then(self.handleSuccess);
    };

    self.openLinkOidcAccountDialog = function () {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/js/dashboard-app/components/common/user.linking.dialog.html',
        controller: LinkOidcController,
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

    self.openUnlinkOidcAccountDialog = function (oidcId) {

      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/js/dashboard-app/components/common/user.linking.dialog.html',
        controller: LinkOidcController,
        controllerAs: '$ctrl',
        resolve: {
          action: function () {
            return 'unlink';
          },
          account: function () {
            return {
              iss: oidcId.issuer,
              sub: oidcId.subject
            }
          }
        }
      });

      modalInstance.result.then(self.handleSuccess);
    };



    self.openRemoveOidcAccountDialog = function (oidcId) {

      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/js/dashboard-app/components/user/oidc/oidc-id.remove.dialog.html',
        controller: RemoveOidcController,
        controllerAs: '$ctrl',
        resolve: {
          user: function () {
            return self.user;
          },
          account: oidcId
        }
      });

      modalInstance.result.then(self.handleSuccess);
    };
  }

  angular.module('dashboardApp').component('userOidc', {
    require: {
      userCtrl: '^user'
    },
    bindings: {
      user: '='
    },
    templateUrl: '/resources/iam/js/dashboard-app/components/user/oidc/user.oidc.component.html',
    controller: [
      '$uibModal', 'toaster', 'ModalService', 'scimFactory', UserOidcController
    ]
  });
})();