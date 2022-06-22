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
angular.module('dashboardApp').factory("scimFactory", ['$q', '$http', '$httpParamSerializer', function ($q, $http, $httpParamSerializer) {

	var urlBase = '/scim';
	var urlUsers = urlBase + '/Users';
	var urlGroups = urlBase + '/Groups';
	var urlMe = urlBase + '/Me';

	var service = {
		getUsers: getUsers,
		getGroups: getGroups,
		getUser: getUser,
		getGroup: getGroup,
		getMe: getMe,
		createGroup: createGroup,
		deleteGroup: deleteGroup,
		createUser: createUser,
		deleteUser: deleteUser,
		addUserToGroup: addUserToGroup,
		removeUserFromGroup: removeUserFromGroup,
		removeMemberFromGroup: removeMemberFromGroup,
		addOpenIDAccount: addOpenIDAccount,
		removeOpenIDAccount: removeOpenIDAccount,
		addSshKey: addSshKey,
		addSshKeyMe: addSshKeyMe,
		removeSshKey: removeSshKey,
		removeSshKeyMe: removeSshKeyMe,
		addX509Certificate: addX509Certificate,
		removeX509Certificate: removeX509Certificate,
		addSamlId: addSamlId,
		removeSamlId: removeSamlId,
		setUserActiveStatus: setUserActiveStatus,
		updateUser: updateUser,
		updateMe: updateMe,
		getAllUsers: getAllUsers,
		getUserProfileConfig: getUserProfileConfig
	};

	return service;

	function getUserProfileConfig() {
		return $http.get("/iam/config/profile", {
			cache: true
		}).then(function (res) {
			return res.data;
		}).catch(function (err) {
			return $q.reject(err);
		});
	}

	function getUsers(startIndex, count) {

		console.info("Getting users from-to: ", startIndex, count);
		var qs = $httpParamSerializer({
			'startIndex': startIndex,
			'count': count
		});
		var url = urlUsers + '?' + qs;

		return $http.get(url);
	}

	function getAllUsers(chunkRequestSize = 100) {

		console.info("Getting all users");

		var deferred = $q.defer();

		var promises = [];
		var users = [];
		var handleResponse = function (response) {
			angular.forEach(response.data.Resources, function (user) {
				users.push(user);
			});
		};
		var handleError = function (error) {
			deferred.reject(error)
		};

		var handleFirstResponse = function (response) {

			var totalResults = response.data.totalResults;
			var lastLoaded = chunkRequestSize;

			while (lastLoaded < totalResults) {
				promises.push(getUsers(lastLoaded + 1, chunkRequestSize));
				lastLoaded = lastLoaded + chunkRequestSize;
			}

			angular.forEach(response.data.Resources, function (user) {
				users.push(user);
			});

			$q.all(promises).then(function (response) {
				angular.forEach(promises, function (p) {
					p.then(handleResponse);
				});
				return users;
			}, handleError);

			return users;
		};

		deferred.resolve(getUsers(1, chunkRequestSize).then(handleFirstResponse, handleError));
		return deferred.promise;
	};

	function getGroups(startIndex, count) {

		console.info("Getting groups from-to: ", startIndex, count);
		var qs = $httpParamSerializer({
			'startIndex': startIndex,
			'count': count
		});
		var url = urlGroups + '?' + qs;

		return $http.get(url);
	};

	function getUser(userId) {

		console.info("Getting user: ", userId);
		var url = urlUsers + '/' + userId;

		return $http.get(url);
	};

	function getGroup(groupId) {

		console.info("Getting group: ", groupId);
		var url = urlGroups + '/' + groupId;

		return $http.get(url);
	};

	function getMe() {

		console.info("Getting Me endpoint");
		var url = urlBase + '/Me';

		return $http.get(url);
	};

	function createGroup(group) {

		console.info("Creating group: ", group);
		var config = {
			headers: {
				'Accept': 'application/scim+json',
				'Content-Type': 'application/scim+json'
			}
		}

		return $http.post(urlGroups, group, config);
	};

	function createUser(user) {

		console.info("Creating user: ", user);
		var config = {
			headers: {
				'Accept': 'application/scim+json',
				'Content-Type': 'application/scim+json'
			}
		};

		return $http.post(urlUsers, user, config);
	}

	function deleteGroup(groupId) {

		console.info("Deleting group: ", groupId);
		var url = urlGroups + '/' + groupId;

		return $http.delete(url);
	}

	function deleteUser(userId) {

		console.info("Deleting user: ", userId);
		var url = urlUsers + '/' + userId;

		return $http.delete(url);
	}

	function addUserToGroup(groupId, scimUser) {

		console.info("Patch groupId, add user ", groupId, scimUser);

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};

		var data = {

			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "add",
				path: "members",
				value: [{
					value: scimUser.id,
					$ref: scimUser.meta.location,
					display: scimUser.displayName
				}]
			}]
		};

		var url = urlGroups + '/' + groupId;

		return $http.patch(url, data, config);
	}

	function removeUserFromGroup(groupId, userId, userLocation, userDisplayName) {

		console.info("Patch groupId, remove user", groupId, userId, userLocation);

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "remove",
				path: "members",
				value: [{
					display: userDisplayName,
					value: userId,
					$ref: userLocation
				}]
			}]
		};
		var url = urlGroups + '/' + groupId;

		return $http.patch(url, data, config);
	}

	function removeMemberFromGroup(groupId, memberId, memberLocation, memberDisplayName) {

		console.info("Patch groupId, remove member", groupId, memberId, memberLocation);

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "remove",
				path: "members",
				value: [{
					display: memberDisplayName,
					value: memberId,
					$ref: memberLocation
				}]
			}]
		};
		var url = urlGroups + '/' + groupId;

		return $http.patch(url, data, config);
	}

	function addOpenIDAccount(userId, account) {

		var url = urlUsers + '/' + userId;

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};

		var data = {

			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "add",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						oidcIds: [account]
					}
				}
			}]
		};


		return $http.patch(url, data, config);
	}

	function removeOpenIDAccount(userId, account) {

		var url = urlUsers + '/' + userId;

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};

		var data = {

			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "remove",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						oidcIds: [account]
					}
				}
			}]
		};

		return $http.patch(url, data, config);
	}

	function addSshKey(userId, key) {

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "add",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						sshKeys: [key]
					}
				}
			}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	}

	function addSshKeyMe(key) {

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "add",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						sshKeys: [key]
					}
				}
			}]
		};

		return $http.patch(urlMe, data, config);
	}

	function removeSshKeyMe(key) {
		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "remove",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						sshKeys: [key]
					}
				}
			}]
		};

		return $http.patch(urlMe, data, config);
	}

	function removeSshKey(userId, key) {

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "remove",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						sshKeys: [key]
					}
				}
			}]
		};

		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	}

	function addX509Certificate(userId, certificate) {

		var url = urlUsers + '/' + userId;

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};

		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "add",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						certificates: [certificate]
					}
				}
			}]
		};

		return $http.patch(url, data, config);
	}

	function removeX509Certificate(userId, certificate) {

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};

		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "remove",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						certificates: [certificate]
					}
				}
			}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	function addSamlId(userId, samlId) {

		var url = urlUsers + '/' + userId;

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "add",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						samlIds: [samlId]
					}
				}
			}]
		};

		return $http.patch(url, data, config);
	}

	function removeSamlId(userId, samlId) {

		console.info("Patch user-id, remove saml-account ", userId, samlId.idpId, samlId.userId);

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "remove",
				value: {
					"urn:indigo-dc:scim:schemas:IndigoUser": {
						samlIds: [{
							"idpId": samlId.idpId,
							"attributeId": samlId.attributeId,
							"userId": samlId.userId
						}]
					}
				}
			}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	function setUserActiveStatus(userId, status) {

		console.info("Patch user-id, set active to ", userId, status);

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: [{
				op: "replace",
				value: {
					active: status
				}
			}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	function updateUser(userId, ops) {

		console.info("Patch user ", userId, ops);

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: ops
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	function updateMe(ops) {

		console.info("Patch current user", ops);

		var config = {
			headers: {
				'Content-Type': 'application/scim+json'
			}
		};
		var data = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			operations: ops
		};

		return $http.patch(urlMe, data, config);
	};


}]);