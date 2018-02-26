/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.up.campus.adlookup;
import javax.websocket.Session;

/**
 *
 * @author MatthewYuen
 */
public class LoginSession {
    private Session session;
    ADLookup query;
    public LoginSession(Session session, ADLookup query) {
        this.session = session;
        this.query = query;
    }
    public Session getSession() {
        return session;
    }
    
    public ADLookup getQuery(){
        return query;
    }
    
    public void deleteSession() {
        session = null;
    }

}
