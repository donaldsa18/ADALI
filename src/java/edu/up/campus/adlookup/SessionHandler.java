/*
 * SessionHandler handles logins, user lookups, and unlocks. It generates a Json 
 * response and sends it back to the client
 * 
 * @author Matthew Yuen
 * @author Anthony Donaldson
 */
package edu.up.campus.adlookup;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import javax.enterprise.context.ApplicationScoped;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.SortedMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.websocket.Session;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.spi.JsonProvider;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import net.jodah.expiringmap.ExpiringMap;
import net.jodah.expiringmap.ExpiringMap.ExpirationPolicy;

@ApplicationScoped
public class SessionHandler {

    //A set of the active sessions
    private final Set<Session> sessions = new HashSet<>();
    private final Map<String,LoginSession> loginSessions;
    
    //The attributes to read from the domain controller
    private final String[] attributes = new String[]{
                "badPasswordTime",
                "lastLogon",
                "pwdLastSet",
                "accountExpires",
                "employeeID",
                "displayName",
                "otherMailbox",
                "mailNickname",
                "lockoutTime",
                "badPwdCount",
                "MemberOf",
                "userPrincipalName",
                "userAccountControl"
            };
    
    //The number of days before a password expires
    private final int pwdDuration;
    
    //The email address domain
    private final String domain;
    
    //The format to use for all datetimes
    private final SimpleDateFormat dateformat = new SimpleDateFormat("MM/dd/yyyy hh:mm:ss a");
    
    //The LDAPS connection string. In order for LDAPS to work, the UPRoot
    //certificate needs to be imported to <glassfish_home>/glassfish/domains/domain1/config/cacerts.jks
    //Use "ldap://domainControllerFQDN:389" or "ldaps://domainControllerFQDN:636"
    private final String connectionStr;
    
    //The distinguished name of the LDAP bind service account
    private final String serviceUser;
    
    //The password for the account above
    private final String servicePass;
    
    //The group which has access to the website
    private final String authGroup;
    
    //The base distinguished name of the domain
    private final String baseDN;
    
    //The number of milliseconds before the websocket connection times out from being idle
    private final long timeout;
    
    //The number of search results to process at a time
    private final int maxResults;
    
    //The regex pattern that extracts a simple username from a distinguished name
    private final Pattern cnPattern = Pattern.compile("(?m)^CN=(.*?),");
    
    //A JSONProvider for use when creating JSON messages
    private final JsonProvider provider = JsonProvider.provider();
    
    //The name of the JNDI resource for the the database connection pool
    private final String jndiDBName;
    
    private final String queryUser = "SELECT username FROM users WHERE username LIKE ?";
    
    //Use all available threads to handle most method calls asynchronously
    private ExecutorService execService;
    
    private final int suggestionTimeout;
    
    private final int maxPages;
    
    private DataSource ds;
    
    /**
     * Constructor for SessionHandler. Loads settings from settings.properties.
     * If the file is not found in the classpath, it uses default values
     * hardcoded below.
     * 
     */
    public SessionHandler() {
        ResourceBundle settings = ResourceBundle.getBundle("settings");

        if(settings != null && settings.containsKey("pwdDuration")) {
            pwdDuration = Integer.parseInt(settings.getString("pwdDuration"));
        }
        else {
            pwdDuration = 143;
            System.out.println("Using default password duration");
        }
        if(settings != null && settings.containsKey("domain")) {
            domain = settings.getString("domain");
        }
        else {
            domain = "";
            System.err.println("No default domain name found! Example: @example.com");
        }
        if(settings != null && settings.containsKey("connectionStr")) {
            connectionStr = settings.getString("connectionStr");
        }
        else {
            connectionStr = "";
            System.err.println("No LDAP connection string found! Example: ldap");
        }
        if(settings != null && settings.containsKey("serviceUser")) {
            serviceUser = settings.getString("serviceUser");
        }
        else {
            serviceUser = "";
            System.err.println("No service user found!");
        }
        if(settings != null && settings.containsKey("servicePass")) {
            servicePass = settings.getString("servicePass");
        }
        else {
            servicePass = "";
            System.err.println("No password found!");
        }
        if(settings != null && settings.containsKey("authGroup")) {
            authGroup = settings.getString("authGroup");
        }
        else {
            authGroup = "";
            System.err.println("No authorization group specified. Example for group admin: authGroup=CN=admin,DC=domain,DC=example,DC=com");
        }
        if(settings != null && settings.containsKey("baseDN")) {
            baseDN = settings.getString("baseDN");
        }
        else {
            baseDN = "";
            System.out.println("No default base distinguished name. Example for domain.example.com: baseDN=DC=domain,DC=example,DC=com");
        }
        if(settings != null && settings.containsKey("timeout")) {
            timeout = Long.parseLong(settings.getString("timeout"))*1000;
        }
        else {
            timeout = TimeUnit.DAYS.toMillis(1);
            System.out.println("Using default timeout");
        }
        if(settings != null && settings.containsKey("resultsPerPage")) {
            maxResults = Integer.parseInt(settings.getString("resultsPerPage"));
        }
        else {
            maxResults = 1000;
            System.out.println("Using default max results");
        }
        if(settings != null && settings.containsKey("jndiName")) {
            jndiDBName = settings.getString("jndiName");
        }
        else {
            jndiDBName = "jdbc/ADUsersMySQL";
            System.out.println("Using default JNDI resource name");
        }
        if(settings != null && settings.containsKey("suggestionTimeout")) {
            suggestionTimeout = Integer.parseInt(settings.getString("suggestionTimeout"));
        }
        else {
            suggestionTimeout = 100;
            System.out.println("Using default search suggestion timeout name");
        }
        if(settings != null && settings.containsKey("maxPages")) {
            maxPages = Integer.parseInt(settings.getString("maxPages"));
        }
        else {
            maxPages = 2;
            System.out.println("Using default max page size");
        }
        
        //Create map that expires old LoginSessions
        loginSessions = ExpiringMap.builder()
            .expiration(timeout, TimeUnit.MILLISECONDS)
            .expirationPolicy(ExpirationPolicy.ACCESSED)
            .build();
        
        //Use JNDI resources to prevent memory leaks and let the glassfish server manage resources
        try {
            InitialContext ctx = new InitialContext();
            
            //Schedule a ping task
            ScheduledExecutorService ses = (ScheduledExecutorService)ctx.lookup("concurrent/__defaultManagedScheduledExecutorService");
            ses.scheduleWithFixedDelay(() -> {
                JsonObject message = provider.createObjectBuilder()
                        .add("action","keepalive")
                        .build();
                sessions.forEach((session) -> {
                    sendToSession(session,message);
                    
                    //Clear search suggestion info periodically due to browser storage clearing
                    if(loginSessions.containsKey(session.getId())) {
                        ADLookup query = loginSessions.get(session.getId()).getQuery();
                        query.completedSearches.clear();
                        query.incompleteSearches.clear();
                    }
                });
            }, timeout/2, timeout/2, TimeUnit.MILLISECONDS);
            
            //Find the ManagedExecutorService to use for submitting asynchronous tasks
            execService = (ExecutorService)ctx.lookup("concurrent/__defaultManagedExecutorService");
            
            //Test the DB connection
            ds = (DataSource) ctx.lookup(jndiDBName);
            Connection conn = ds.getConnection();
            conn.close();
            
        } catch (SQLException ex) {
            System.out.println("DB connection failed. "+ex);
        } catch(NamingException ex) {
            System.out.println("Couldn't find JNDI resource. "+ex);
        }
    }
    
    public void addSession(Session session) {
        session.setMaxIdleTimeout(timeout);
        sessions.add(session);
    }

    public void removeSession(Session session) {
        //Keep loginsession because its token could be used later
        if(session != null) {
            LoginSession loginSession = loginSessions.get(session.getId());
            if(loginSession != null) {
                loginSession.deleteSession();
            }
            sessions.remove(session);
        }
    }
    public void removeLoginSession(Session session) {
        loginSessions.remove(session.getId());
        sessions.remove(session);
    }
    
    //Reference LoginSession to prevent expiration
    public void keepLoginSession(Session session) {
        loginSessions.get(session.getId());
    }

    public void login(Session session, String username, String password) {
        //Use another thread to avoid blocking the WebSocketServer
        execService.execute(new Runnable() {
            @Override
            public void run() {
                JsonObject message = null;
                try {
                    if (username == null || "".equals(username) || password == null || "".equals(password)) {
                        //System.out.println("Empty username or password");
                        throw new Exception("Empty username or password");
                    }
                    //Authenticate by creating new ADLookup which does a bind
                    ADLookup query = new ADLookup(connectionStr, username, password, baseDN, serviceUser, servicePass, authGroup);
                    loginSessions.put(session.getId(),new LoginSession(session, query));
                    message = provider.createObjectBuilder()
                            .add("action", "loginresponse")
                            .add("message", "success")
                            .add("token", session.getId())
                            .build();
                    System.out.println("Login success.");
                } catch (Exception e) {
                    System.out.println("Login failed.\n"+e);
                    message = provider.createObjectBuilder()
                            .add("action", "loginresponse")
                            .add("message", "fail")
                            .build();
                } finally {
                    sendToSession(session, message);
                }
            }
        });
    }
    
    public void login(Session session, String token) {
        execService.execute(new Runnable() {
            @Override
            public void run() {
                JsonObject message = null;
                try {
                    System.out.println("Attempting token login.");
                    if (token == null || "".equals(token)) {
                        throw new Exception("Empty token");
                    }
                    if(token.length() != 38) {
                        throw new Exception("Token is an invalid size");
                    }
                    String trimToken = token.substring(1, token.length()-1);
                    LoginSession oldLogin = loginSessions.get(trimToken);
                    if(oldLogin == null) {
                        throw new Exception("Invalid token");
                    }
                    //Reuse old ADQuery object
                    loginSessions.put(session.getId(),new LoginSession(session, oldLogin.getQuery()));
                    
                    //Delete original session
                    loginSessions.remove(trimToken);
                    sessions.remove(oldLogin.getSession());
                    message = provider.createObjectBuilder()
                            .add("action", "loginresponse")
                            .add("message", "success")
                            .add("token", session.getId())
                            .build();
                    System.out.println("Login success");
                //Don't need to reply if failed
                } catch (Exception e) {
                    message = provider.createObjectBuilder()
                        .add("action", "cachedlogin")
                        .add("message", "failed")
                        .build();
                    System.out.println("Login failed.\n"+e);
                } finally {
                    sendToSession(session, message);
                }
            }
        });
    }

    public void unlock(Session session, String username) {
        execService.execute(new Runnable() {
            @Override
            public void run() {
                if(loginSessions.containsKey(session.getId())) {
                    ADLookup query = loginSessions.get(session.getId()).getQuery();
                    if(query != null) {
                        boolean result = query.setAttrib(username, "lockoutTime", "0");

                        if (result == false) {
                            JsonObject message = provider.createObjectBuilder()
                                    .add("action", "locked")
                                    .build();
                            sendToSession(session, message);
                            return;
                        } else {
                            JsonObject message = provider.createObjectBuilder()
                                    .add("action", "unlocked")
                                    .build();
                            sendToSession(session, message);
                            return;
                        }
                    }
                }
                JsonObject message = provider.createObjectBuilder()
                        .add("action", "nologin")
                        .build();
                sendToSession(session, message);
            }
        });
    }
    
    public void searchUsers(Session session, String username, long whenSent) {
        execService.execute(new Runnable() {
            @Override
            public void run() {
                if(!loginSessions.containsKey(session.getId()) || username.isEmpty()) {
                    return;
                }
                ADLookup query = loginSessions.get(session.getId()).getQuery();
                if(query == null) {
                    return;
                }
                long startTime = System.currentTimeMillis();
                long pingTime = (startTime-whenSent)*2;
                //System.out.println("Searching for "+username);
                //Check if the client already has all possible usernames cached for this prefix
                String prefix = query.completedSearches.floor(username);
                
                if((prefix != null && username.startsWith(prefix))) {
                    System.out.println("Prefix found");
                    return;
                }
                try(Connection conn = ds.getConnection()) {
                    //System.out.println("Established connection in "+(System.currentTimeMillis()-startTime)+"ms");
                    
                    //Search for the closest key in incompleteSearches
                    ArrayList<String> excludeStrings = new ArrayList<>();
                    String firstEntry = query.incompleteSearches.floorKey(username);
                    if(firstEntry == null) {
                        firstEntry = query.incompleteSearches.ceilingKey(username);
                    }
                    String notBetween = "";
                    if(firstEntry != null) {
                        //Construct a string with the last character incremented (ex. username => usernamf)
                        char[] usernameArr = username.toCharArray();
                        usernameArr[usernameArr.length-1]++;
                        String nextUsername = new String(usernameArr);
                        //username.substring(0, username.length()-1)+Character.toString((char) (username.charAt(username.length()-1)+1));
                        System.out.print("Next username is "+nextUsername);
                        //Make sure the map is not empty
                        if(nextUsername.compareTo(firstEntry) > 0) {
                            //Find all matching ranges and their keys
                            SortedMap<String,Boolean> excludeMap = query.incompleteSearches.subMap(firstEntry,true,nextUsername,false);
                            String[] keys = excludeMap.keySet().toArray(new String[0]);
                            for(int i=0;i<keys.length;i++) {
                                //Check if keys[i] and keys[i+1] form a range or if the last element starts a range
                                if(excludeMap.get(keys[i]) == true && (i == keys.length-1 || excludeMap.get(keys[i+1]) == false)) {
                                    excludeStrings.add(keys[i]);
                                    
                                    //This is the last element and it starts an incomplete range
                                    if(i == keys.length-1) {
                                        //A search excluding everything in between will return nothing
                                        //keys[i] <= username
                                        if(username.compareToIgnoreCase(keys[i]) >= 0) {
                                            System.out.print("Ignoring search for "+username+" because an incomplete search starts with "+keys[i]);
                                            return;
                                        }
                                        excludeStrings.add(nextUsername);
                                    }
                                    //This is a range pair
                                    else {
                                        excludeStrings.add(keys[i+1]);
                                    }
                                    notBetween += " AND username NOT BETWEEN ? AND ?";
                                }
                            }
                        }
                    }

                    int pageNum = 0;
                    int totalResults = 0;
                    //For each query
                    for(int numResults = maxResults; numResults == maxResults; pageNum++) {
                        //Reset results to 0 before executing the query
                        numResults = 0;

                        //Construct the query string
                        StringBuilder queryBuilder = new StringBuilder();
                        queryBuilder.append(queryUser)
                            .append(notBetween)
                            .append(" LIMIT ")
                            .append((pageNum*maxResults))
                            .append(", ")
                            .append(maxResults);
                        PreparedStatement stmtQuery = conn.prepareStatement(queryBuilder.toString());

                        //Set all variable strings in the query
                        stmtQuery.setString(1, username+"%");
                        for(int i=0;i<excludeStrings.size();i++) {
                            stmtQuery.setString(i+2,excludeStrings.get(i));
                        }

                        System.out.println("Executing: "+stmtQuery);

                        //Execute the query and put all results into a JSON Array
                        ResultSet rs = stmtQuery.executeQuery();
                        JsonArrayBuilder arrBuilder = Json.createArrayBuilder();
                        String lastUsername = null;

                        while(rs.next()) {
                            lastUsername = rs.getString(1);
                            arrBuilder.add(lastUsername);
                            numResults++;
                        }
                        totalResults += numResults;
                        //Build the JSON response and send immediately
                        JsonObject message = provider.createObjectBuilder()
                                .add("action","suggestion")
                                .add("suggestion",arrBuilder)
                                .build();
                        sendToSession(session, message);

                        //Search is complete if the results are less than the limit
                        if(numResults < maxResults) {
                            query.completedSearches.add(username);
                            System.out.println("Searching for "+totalResults+" usernames matching "+username+" took "+(System.currentTimeMillis()-startTime)+"ms");
                        }
                        //Timeout a search if it would take more than 100ms to arrive
                        else if((System.currentTimeMillis()-startTime+pingTime) > suggestionTimeout) {
                            System.out.println("Searching for "+totalResults+" usernames matching "+username+" timed out after "+(System.currentTimeMillis()-startTime)+"ms with ping="+pingTime+".");
                            numResults = -1;
                            combineRanges(username,lastUsername,query);
                        }
                        //Search is complete if the number of pages reaches the max threshold
                        else if(pageNum >= maxPages) {
                            System.out.println("Search for "+username+" was truncated at "+totalResults+" results after "+(System.currentTimeMillis()-startTime)+"ms.");
                            numResults = -1;
                            combineRanges(username,lastUsername,query);
                        }
                    }
                    conn.close();
                } catch (SQLException ex) {
                    System.out.println("SQL query error. "+ex);
                }
            }
        });
    }
    
    public void getUserInfo(Session session, String username) {
        execService.execute(new Runnable() {
            @Override
            public void run() {
                //Search for corresponding loginsession
                if(loginSessions.containsKey(session.getId())) {
                    ADLookup query = loginSessions.get(session.getId()).getQuery();
                    if(query != null) {
                        //Lookup attributes in AD
                        String[] result = query.search(attributes, username);

                        if (result == null) {
                            //If no user is found, send an error
                            JsonObject message = provider.createObjectBuilder()
                                    .add("action", "nouser")
                                    .build();
                            sendToSession(session, message);
                            return;
                        }
                        else {
                            //Calculate when password expires 
                            String passwordSetToExpire = "Never";
                            String daysLeft = "\u221e";
                            int userBitmask = Integer.parseInt(result[12]);
                            //Check that the flag ADS_UF_DONT_EXPIRE_PASSWD is set
                            //from https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx
                            if((userBitmask & ADLookup.DONT_EXPIRE_PASSWORD) != ADLookup.DONT_EXPIRE_PASSWORD) {
                                if(result[2] != null && !result[2].isEmpty()) {
                                    Calendar cal = Calendar.getInstance();
                                    try {
                                        //Calculate when the password will expire
                                        long currentTime = cal.getTimeInMillis();
                                        cal.setTime(new Date((Long.parseLong(result[2]) / 10000) - 11644473600000L));
                                        cal.add(Calendar.DATE, pwdDuration);
                                        passwordSetToExpire = dateformat.format(cal.getTime());
                                        
                                        //Calculate the number of days before the password expires
                                        daysLeft = Long.toString(TimeUnit.DAYS.convert(cal.getTimeInMillis()-currentTime, TimeUnit.MILLISECONDS));
                                    } catch(NumberFormatException e) {}
                                }
                            }
                            
                            //Convert filetime to a date
                            for (int i = 0; i < 4; i++) {
                                if ("9223372036854775807".equals(result[i]) || "0".equals(result[i])) {
                                    result[i] = "Never";
                                } else {
                                    result[i] = fileTimeToDateTime(result[i]);
                                }
                            }
                            
                            //Append domain to email
                            if(result[7].isEmpty()) {
                                result[7] = result[11];
                            }
                            else {
                                result[7] = result[7] + domain;
                            }

                            result[10] = trimDistinguishedName(result[10]);
                            //Build Json response to browser
                            JsonObjectBuilder builder = Json.createObjectBuilder();
                            for (int i = 0; i < attributes.length-2; i++) {
                                if (result[i] == null || result[i].isEmpty()) {
                                    result[i] = "N/A";
                                }
                                builder.add(attributes[i].toLowerCase(), result[i]);
                            }
                            builder.add("action", "userinfo")
                                   .add("daysleft", daysLeft)
                                   .add("passwordsettoexpire", passwordSetToExpire);

                            JsonObject message = builder.build();
                            sendToSession(session, message);
                            return;
                        }
                    } 
                }
                //If anything failed, logout the user
                JsonObject message = provider.createObjectBuilder()
                        .add("action", "nologin")
                        .build();
                sendToSession(session, message);
            }
        });   
    }
    
    /**
     * Sends a JsonObject to a client
     * 
     * @param  session the session to send the message to
     * @param  message the message to send
     */
    private void sendToSession(Session session, JsonObject message) {
        try {
            session.getBasicRemote().sendText(message.toString());
        } catch (IOException ex) {
            removeSession(session);
            Logger.getLogger(SessionHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private String trimDistinguishedName(String dn) {
        if(dn != null && !dn.isEmpty()) {
            Matcher matcher = cnPattern.matcher(dn);

            //Append each group to an HTML encoded list
            StringBuilder builder = new StringBuilder();
            while(matcher.find()) {
                builder.append(matcher.group(1))
                       .append("<br/>");
            }
            return builder.toString();
        }
        else {
            return "N/A";
        }
    }
    
    private void combineRanges(String firstUsername, String lastUsername, ADLookup query) {
        if(firstUsername == null || firstUsername.isEmpty() || lastUsername == null || lastUsername.isEmpty()) {
            return;
        }
        Entry<String,Boolean> firstEntry = query.incompleteSearches.floorEntry(firstUsername);
        Entry<String,Boolean> lastEntry = query.incompleteSearches.ceilingEntry(lastUsername);
        Map<String,Boolean> toRemove = null;
        
        //Get the subMap between firstEntry and lastEntry even if one of them is null
        if(firstEntry == null && lastEntry != null) {
            toRemove = query.incompleteSearches.headMap(lastEntry.getKey(),false);
        }
        else if(firstEntry != null && lastEntry == null) {
            toRemove = query.incompleteSearches.tailMap(firstEntry.getKey(),false);
        }
        else if(firstEntry != null && lastEntry != null) {
            toRemove = query.incompleteSearches.subMap(firstEntry.getKey(),false,lastEntry.getKey(),false);
        }
        
        //Remove all entries between this range
        if(toRemove != null) {
            query.incompleteSearches.keySet().removeAll(toRemove.keySet());
        }
        
        //Have to create a new starting entry if no overlap
        if(firstEntry == null || firstEntry.getValue() == false) {
            query.incompleteSearches.put(firstUsername, Boolean.TRUE);
            //System.out.println("Added range start at "+firstUsername);
        }

        //Have to create a new ending entry if no overlap
        if(lastEntry == null || lastEntry.getValue() == true) {
            query.incompleteSearches.put(lastUsername, Boolean.FALSE);
            //System.out.println("Added range end at "+lastUsername);
        }
        System.out.println("Incomplete searches: "+query.incompleteSearches);
    }
    
    /**
     * Returns a datetime string converted from a filetime. A filetime
     * is the time in  100-nanosecond intervals since January 1, 1601 UTC.
     * 
     * @param  time the filetime to convert as a string in decimal format
     * @return      the corresponding datetime
     */
    private String fileTimeToDateTime(String time) {
        try {
            if(time != null && !time.isEmpty()) {
                long ms = Long.parseLong(time) / 10000L;
                long unixtime = ms - 11644473600000L;
                Date date = new Date(unixtime);
                String formattedDate = dateformat.format(date);
                return formattedDate;
            }
        }
        catch(NumberFormatException e) {
            
        }
        return "N/A";
    }
}