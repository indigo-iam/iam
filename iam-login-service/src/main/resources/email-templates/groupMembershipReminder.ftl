Dear Group Manager,

there are ${requestCount} pending membership request(s) for group ${groupName} awaiting your action:

<#list pendingUsers as user>
  Name: ${user.name}
  Username: ${user.username}
  Requested on: ${user.requestDate}
  Notes: ${user.notes}

</#list>
You can approve or reject these requests by following the link below:

${indigoDashboardUrl}


The ${organisationName} registration service
