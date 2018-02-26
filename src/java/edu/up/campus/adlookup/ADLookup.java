/*
 * ADLookup handles all connections to the domain controller. It tests a user's
 * credentials when initializing and can search or modify attributes with those
 * creditials.
 * 
 * @author Matthew Yuen
 * @author Anthony Donaldson
 */

package edu.up.campus.adlookup;

import javax.naming.directory.*;
import javax.naming.*;
import java.util.Hashtable;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ConcurrentSkipListSet;

public class ADLookup {
    public static final int DONT_EXPIRE_PASSWORD = 0x00010000;
    protected Hashtable<String, String> env;
    protected final String base;
    //protected HashSet<String> suggestedUsers = new HashSet<>();
    public ConcurrentSkipListSet<String> completedSearches = new ConcurrentSkipListSet<>();
    //public ConcurrentSkipListMap<String,Integer> incompleteSearchStrings = new ConcurrentSkipListMap<>();
    public ConcurrentSkipListMap<String,Boolean> incompleteSearches = new ConcurrentSkipListMap<>();
    
    public ADLookup(String domain, String username, String password, String baseStr, String serviceUser, String servicePass, String authGroup) throws Exception {
        //Initialize LDAP context hashtable with service account (insecurely)
        env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, serviceUser);
        env.put(Context.SECURITY_CREDENTIALS, servicePass);
        env.put(Context.PROVIDER_URL, domain);
        
        //Timeout a connection if it cannot be established within .5 s
        env.put("com.sun.jndi.ldap.connect.timeout", "500");
        
        //Abort a read attempt if the server doesn't respond in 5 seconds
        env.put("com.sun.jndi.ldap.read.timeout", "5000");
        
        base = baseStr;
        
        //Search for user in AD
        DirContext ctx = new InitialDirContext(env);
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        //Search for the user with the matching sAMAccountName
        String filter = "(&(objectClass=user)(sAMAccountName=" + escapeLDAPSearchFilter(username) + "))";
        NamingEnumeration<SearchResult> answer = ctx.search(base, filter, searchCtls);
        if (answer.hasMoreElements()) {
            //System.out.println("Found user");
            
            //Find full name to use for authentication
            Attributes attrs = answer.next().getAttributes();
            String distName = attrs.get("distinguishedName").get().toString();
            
            NamingEnumeration groups = attrs.get("memberof").getAll();
            
            boolean authenticated = false;
            //Check for membership in authorized group
            while (groups.hasMore()) {
                String groupName = groups.next().toString();
                if (authGroup.equals(groupName)) {
                    authenticated = true;
                    break;
                }
            }
            if(authGroup == null || authenticated) {
                //System.out.println(username + " is authorized.");
                ctx.close();
                //Replace the service account's credentials with the user's credentials
                env.remove(Context.SECURITY_PRINCIPAL);
                env.remove(Context.SECURITY_CREDENTIALS);
                env.put(Context.SECURITY_PRINCIPAL, distName);
                env.put(Context.SECURITY_CREDENTIALS, password);
                
                //Use a pool of LDAP connections for efficiency
                //Enable it after all the changes to the environment are done
                env.put("com.sun.jndi.ldap.connect.pool", "true");
                
                //Remove a connection from the pool after 1 min
                env.put("com.sun.jndi.ldap.connect.pool.timeout","60000");
                
                //Test credentials by binding with them
                ctx = new InitialDirContext(env);
                ctx.close();
                
                //System.out.println("Password is correct.");
            }
            else {
                ctx.close();
                throw new Exception("User not authorized");
            }
        } else {
            ctx.close();
            throw new Exception("Didn't find user");
        }
        
    }

    public String[] search(String[] attributes, String user) {
        try {
            //Create a new context to avoid timeout error
            DirContext ctx = new InitialDirContext(env);
            //Execute search
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String filter = "(&(objectClass=user)(sAMAccountName=" + escapeLDAPSearchFilter(user) + "))";
            NamingEnumeration<SearchResult> answer = ctx.search(base, filter, searchCtls);
            if (answer.hasMoreElements()) {
                String[] results = new String[attributes.length];
                SearchResult sr = answer.next();
                //System.out.println("Name: "+sr.getName());
                Attributes attrs = sr.getAttributes();
                if (attrs == null) {
                    throw new NamingException("User attributes are null.");
                }
                for (int i = 0; i < attributes.length; i++) {
                    results[i] = "";
                    if (attrs.get(attributes[i]) != null) {
                        NamingEnumeration groups = attrs.get(attributes[i]).getAll();
                        while (groups.hasMore()) {
                            results[i] += groups.next().toString()+"\n";
                        }
                        if(!("".equals(results[i]))) {
                            results[i] = results[i].substring(0,results[i].length()-1);
                        }
                        if (results[i] == null || results[i].isEmpty()) {
                            results[i] = "N/A";
                        }
                        //System.out.println(attributes[i]+":"+results[i]);
                    }
                }
                
                //Close connection to save resources on the domain controller
                ctx.close();
                return results;
            }
            ctx.close();
        } catch (NamingException e) {
            System.err.println("NamingException when searching. " + e);
        } catch (NullPointerException e) {
            System.err.println("Couldn't initialize LDAP context. " + e);
        }
        return null;
    }
    
    public boolean setAttrib(String name, String attrib, String setting) {
        
        //Create ModificationItem to replace one attribute 
        ModificationItem[] mod = new ModificationItem[1];
        mod[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(attrib, setting));
        try {
            //Create a new context to avoid timeout error
            DirContext ctx = new InitialDirContext(env);
            
            //Search for the user's distinguished name
            String[] results = this.search(new String[]{"distinguishedName"}, name);
            
            //Modify the user's attribute
            ctx.modifyAttributes(results[0], mod);
            return true;
        } catch (NamingException e) {
            System.err.println("NamingException when modifying " + attrib +". "+ e);
        } catch (NullPointerException e) {
            System.err.println("Couldn't initialize LDAP context. " + e);
        }
        return false;
    }
    
    //https://www.owasp.org/index.php/Preventing_LDAP_Injection_in_Java
    public static String escapeLDAPSearchFilter(String filter) {
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < filter.length(); i++) {
           char curChar = filter.charAt(i);
           switch (curChar) {
               case '\\':
                   sb.append("\\5c");
                   break;
               case '*':
                   sb.append("\\2a");
                   break;
               case '(':
                   sb.append("\\28");
                   break;
               case ')':
                   sb.append("\\29");
                   break;
               case '\u0000': 
                   sb.append("\\00"); 
                   break;
               default:
                   sb.append(curChar);
           }
       }
       return sb.toString();
   }
}
