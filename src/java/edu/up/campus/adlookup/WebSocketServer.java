/*
 * WebSocketServer receives all Websocket messages and passes the relevant info
 * to SessionHandler to execute the application logic.
 * 
 * @author Matthew Yuen
 * @author Anthony Donaldson
 */
package edu.up.campus.adlookup;

import javax.websocket.server.ServerEndpoint;
import javax.inject.Inject;
import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.enterprise.context.ApplicationScoped;
import java.io.StringReader;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;   
import java.util.logging.Level;
import java.util.logging.Logger;

@ApplicationScoped

//The relative path where the websocket server is hosted
@ServerEndpoint("/actions")
public class WebSocketServer {
    @Inject
        private SessionHandler sessionHandler;
    
    @OnOpen
    public void open(Session session) {
        sessionHandler.addSession(session);
    }

    @OnClose
    public void close(Session session) {
        sessionHandler.removeSession(session);
    }

    @OnError
    public void onError(Throwable error) {
        Logger.getLogger(WebSocketServer.class.getName()).log(Level.SEVERE, null, error);
    }

    @OnMessage
    public void handleMessage(String message, Session session) {
        try (JsonReader reader = Json.createReader(new StringReader(message))) {
            JsonObject jsonMessage = reader.readObject();
            String action = jsonMessage.getString("action");
            if ("login".equals(action)) {
                String username = jsonMessage.getString("username");
                String password = jsonMessage.getString("password");
                System.out.println("Logging in as " + username);
                sessionHandler.login(session, username, password);
            }
            else if ("getuserinfo".equals(action)) {
                String username = jsonMessage.getString("user");
                System.out.println("Getting user info for " + username);
                sessionHandler.getUserInfo(session, username);
            }
            else if("unlock".equals(action)) {
                String username = jsonMessage.getString("user");
                System.out.println("Unlocking " + username + "'s account");
                sessionHandler.unlock(session, username);
            }
            else if("suggestion".equals(action)) {
                String username = jsonMessage.getString("user");
                long timestamp = jsonMessage.getJsonNumber("timestamp").bigDecimalValue().longValue();
                //System.out.println("Searching for " + username);
                sessionHandler.searchUsers(session, username,timestamp);
            }
            else if("cachedlogin".equals(action)) {
                String token = jsonMessage.get("token").toString();
                sessionHandler.login(session,token);
            }
            else if("logout".equals(action)) {
                sessionHandler.removeLoginSession(session);
            }
            else if("keepalive".equals(action)) {
                sessionHandler.keepLoginSession(session);
            }
            else {
                System.out.println("Invalid action: "+action);
            }
        }
    }
}    