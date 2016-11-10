angular.module('dashboardApp').factory("scimFactory", [ '$http', '$httpParamSerializer', function($http, $httpParamSerializer) {

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
		addOpenIDAccount: addOpenIDAccount,
		removeOpenIDAccount: removeOpenIDAccount,
		addSshKey: addSshKey,
		removeSshKey: removeSshKey,
		addX509Certificate: addX509Certificate,
		removeX509Certificate: removeX509Certificate,
		addSamlId: addSamlId,
		removeSamlId: removeSamlId,
		setUserActiveStatus: setUserActiveStatus,
		updateUser: updateUser,
		updateMe: updateMe
	}
	
	return service;

	function getUsers(startIndex, count) {
		
		console.info("Getting users from-to: ", startIndex, count);
		var qs = $httpParamSerializer({
			'startIndex': startIndex,
			'count': count
		});
		var url = urlUsers + '?' + qs;
		
		return $http.get(url);
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
			headers : {
				'Accept' : 'application/scim+json',
				'Content-Type' : 'application/scim+json'
			}
		}

		return $http.post(urlGroups, group, config);
	};
	
	function createUser(user) {

		console.info("Creating user: ", user);
		var config = {
			headers : {
				'Accept' : 'application/scim+json',
				'Content-Type' : 'application/scim+json'
			}
		}

		return $http.post(urlUsers, user, config);
	};
	
	function deleteGroup(groupId) {
		
		console.info("Deleting group: ", groupId);
		var url = urlGroups + '/' + groupId;

		return $http.delete(url);
	};
	
	function deleteUser(userId) {
		
		console.info("Deleting user: ", userId);
		var url = urlUsers + '/' + userId;

		return $http.delete(url);
	};
	
	function addUserToGroup(groupId, scimUser) {
		
		console.info("Patch groupId, add user ", groupId, scimUser);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
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
	};

	function removeUserFromGroup(groupId, userId, userLocation, userDisplayName) {
		
		console.info("Patch groupId, remove user", groupId, userId, userLocation);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
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
	};

	function addOpenIDAccount(userId, issuer, subject) {
		
		console.info("Patch user-id, add oidc account ", userId, issuer, subject);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
			
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							oidcIds: [{
								"issuer": issuer,
								"subject": subject
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	function removeOpenIDAccount(userId, issuer, subject) {
		
		console.info("Patch user-id, remove oidc account ", userId, issuer, subject);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
			
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							oidcIds: [{
								"issuer": issuer,
								"subject": subject
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	function addSshKey(userId, label, isPrimary, value) {
		
		console.info("Patch user-id, add ssh-key ", userId, label, value);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							sshKeys: [{
								"display": label,
								"primary": isPrimary,
								"value": value
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};

	function removeSshKey(userId, fingerprint) {
		
		console.info("Patch user-id, remove ssh-key ", userId, fingerprint);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							sshKeys: [{
								"fingerprint": fingerprint
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	function addX509Certificate(userId, label, isPrimary, value) {
		
		console.info("Patch user-id, add ssh-key ", userId, label, value);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						x509Certificates: [{
								"display": label,
								"primary": isPrimary,
								"value": value
							}]
						}
					}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	function removeX509Certificate(userId, value) {
		
		console.info("Patch user-id, add ssh-key ", userId, value);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						x509Certificates: [{
								"value": value
							}]
						}
					}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	function addSamlId(userId, samlIdpId, samlUserId) {
		
		console.info("Patch user-id, add saml-account ", userId, samlIdpId, samlUserId);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							samlIds: [{
								"idpId": samlIdpId,
								"userId": samlUserId
								}
							]
						}
					}
				}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	function removeSamlId(userId, samlId) {
		
		console.info("Patch user-id, remove saml-account ", userId, samlId.idpId, samlId.userId);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							samlIds: [{
								"idpId": samlId.idpId,
								"userId": samlId.userId
								}
							]
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
				headers: { 'Content-Type': 'application/scim+json' }
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
				headers: { 'Content-Type': 'application/scim+json' }
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
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: ops
			};

		return $http.patch(urlMe, data, config);
	};

	return scimFactory;
} ]);
