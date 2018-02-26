# ADLookup

ADLookup is a Java EE project that can lookup users from a Active Directory server.

## Building
Prerequisites:
 * JDK 8+
 * Ant or Netbeans IDE

Build the project:
```
ant
```

## Deployment
 * ADLookup needs a Java EE app server such as [Glassfish](https://javaee.github.io/glassfish/) or [TomEE](http://tomee.apache.org/) to run.
 * Nginx should redirect all HTTP requests to HTTPS
 * From within the console, you can deploy a new version of ADLookup to the server

### Config
 * There is a config file for ADLookup here:
```
/home/glassfish/glassfish4/glassfish/domains/domain1/lib/classes/settings.properties
```
 * This config file is used to change the ldap connection url, service account, authentication group, and a few other settings. Here is an example:
```
attributes=badPasswordTime,lastLogon,pwdLastSet,accountExpires,lastLogonTimestamp,employeeID,displayName,otherMailbox,mailNickname,lockoutTime
pwdDuration=143
domain=@example.com
connectionStr=ldaps://DomainControllerFQDN.example.com:636
serviceUser=CN=adlookup,OU=service accounts,DC=domain,DC=example,DC=com
servicePass=myPassword
authGroup=CN=admins,CN=Users,DC=domain,DC=example,DC=com
baseDN=DC=domain,DC=example,DC=com
resultsPerPage=1000
jndiName=jdbc/ADUsersMySQL
timeout=86400
suggestionTimeout=70
maxPages=2
```
### SSL
 * In order to configure SSL, you must import certificates to:
```
/home/glassfish/glassfish4/glassfish/domains/domain1/config/cacerts.jks
/home/glassfish/glassfish4/glassfish/domains/domain1/config/keystore.jks
```
 * The SSL private key must be imported to keystore.jks
 * The public keys used for LDAPS must be imported to cacerts.jks
 * The keystore's password is the default password: changeit
 * Once the certificates are imported, the server needs to know the wildcard's nickname to use it for https.
 * The Http Listener http-listener-2 must be configured with the SSL Certificate NickName:
```
Configurations->server-config->HTTP Service->Http Listeners->http-listener-2->SSL->Certificate NickName
```
