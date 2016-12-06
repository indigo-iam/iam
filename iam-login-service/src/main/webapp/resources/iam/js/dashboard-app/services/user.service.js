'use strict'

angular.module('dashboardApp').factory('UserService', UserService);

UserService.$inject =
    ['$q', '$rootScope', 'scimFactory', 'Authorities', 'Utils'];

function UserService($q, $rootScope, scimFactory, Authorities, Utils) {
  var service = {getUser: getUser, getMe: getMe, updateLoggedUserInfo: updateLoggedUserInfo};

  return service;

  function getMe(){
    return scimFactory.getMe().then(function(r){
      var user = r.data;
      user.authorities = getUserAuthorities();
      return user;
    });
  }

  function getUser(userId) {
    return $q
        .all([scimFactory.getUser(userId), Authorities.getAuthorities(userId)])
        .then(function(result) {
          var user = result[0].data;
          user.authorities = result[1].data.authorities;
          return user;
        })
        .catch(function(error) {
          console.error('Error loading user information: ', error);
          return $q.reject(error);
        });
  }

  function updateLoggedUserInfo() {
    $rootScope.loggedUser = Utils.getLoggedUser();
    $rootScope.isRegistrationEnabled = Utils.isRegistrationEnabled();

    var promises = [];

    promises.push(scimFactory.getMe().then(function(r) {
      $rootScope.loggedUser.me = r.data;
    }));

    if (Utils.isAdmin()) {
      promises.push(
          scimFactory.getUsers(1, 1).then(function(r) {
            $rootScope.loggedUser.totUsers = r.data.totalResults;
          }),
          scimFactory.getGroups(1, 1).then(function(r) {
            $rootScope.loggedUser.totGroups = r.data.totalResults;
          }));
    }

    return $q.all(promises)
        .then(function(data) {
          console.debug('Logged user info loaded succesfully');
        })
        .catch(function(error) {
          console.error('Error loading logged user info ' + error);
        });
  }
}