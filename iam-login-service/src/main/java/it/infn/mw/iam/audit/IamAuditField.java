package it.infn.mw.iam.audit;

public interface IamAuditField {
  final String source = "source";
  final String category = "category";
  final String type = "type";
  final String principal = "principal";
  final String message = "message";
  final String details = "details";
  final String failureType = "failureType";
  final String target = "target";
  final String generatedBy = "generatedBy";
  final String accountUuid = "accountUuid";
  final String user = "user";
  final String previousAccountUuid = "previousAccountUuid";
  final String previousAccountUsername = "previousAccountUsername";
  final String extAccountIssuer = "extAccIssuer";
  final String extAccountSubject = "extAccSubject";
  final String extAccountType = "extAccountType";
  final String updateType = "updateType";
  final String authority = "authority";
  final String groupUuid = "groupUuid";
  final String groupName = "groupName";
  final String previousGroupUuid = "previousGroupUuid";
  final String previousGroupName = "previousGroupName";
  final String resetKey = "resetKey";
  final String confirmationKey = "confirmationKey";
  final String requestUuid = "requestUuid";
  final String requestStatus = "requestStatus";

}
