var socket = null;
var user = "";
var ubutton = null;
var lockMsg = null;
var userSuggestions = null;
//var startTime = 0;
function onMessage(event) {
    var info = JSON.parse(event.data);
    if (info.action === "loginresponse"){
        if (info.message === "success"){
            //Hide the login box
            document.getElementById("loginerror").style.display = 'none';
            document.getElementById("begin").style.display = 'none';
            
            //Show the search bar
            document.getElementById("middle").style.display = '';
            document.getElementById("Userbox").focus();
            
            //Save the login token
            window.localStorage.setItem("token",info.token);
        }
        else {
            //Display the login error message
            document.getElementById("loginerror").style.display = '';
        }
    }
    else if (info.action === "userinfo"){
        //Show the user info and populate the content div with the table
        document.getElementById("usererror").style.display = 'none';
        document.getElementById("content").style.display = '';
        displayUserInfo(info);
    }
    else if (info.action === "locked"){
        //Unlock failed
        ubutton.style.display = 'none';
        lockMsg.nodeValue = "Locked";
        displayUserInfo(info);
    }
    else if (info.action === "unlocked"){
        //Unlock success, so update the message in the table
        ubutton.style.display = 'none';
        lockMsg.nodeValue = "Unlocked";
    }
    else if (info.action === "nologin"){
        //Login failed, so display an error and show the login screen
        document.getElementById("loginerror").style.display = 'none';
        document.getElementById("begin").style.display = '';
        document.getElementById("middle").style.display = 'none';
        var content = document.getElementById("content");
        if (content.firstChild) {
            content.removeChild(content.firstChild);
        }
    }
    else if (info.action === "nouser"){
        //User not found, so show error and clear content div
        var form = document.getElementById("userinfoForm");
        var user = form.elements["User"].value;
        document.getElementById("usererror").innerHTML = user+' not found';
        document.getElementById("usererror").style.display = '';
        document.getElementById("content").style.display = 'none';
        var content = document.getElementById("content");
        if (content.firstChild) {
            content.removeChild(content.firstChild);
        }
    }
    else if (info.action === "suggestion"){
        //var now = performance.now()-startTime;
        //console.log("Suggestions received after "+now+" ms.");
        
        //Add users to typeahead engine
        userSuggestions.add(info.suggestion);
        
        //Refresh typeahead by clearing and setting the username
        var prevVal = document.getElementById("userinfoForm").elements["User"].value;
        $('.typeahead').typeahead('val','').typeahead('val',prevVal);
        
        //now = performance.now()-startTime;
        //console.log("Suggestions added after "+now+" ms.");
    }
    else if (info.action === "cachedlogin" && info.message === "failed"){
        //Show the login page and delete the bad token
        document.getElementById("begin").style.display = '';
        window.localStorage.removeItem("token");
    }
    else if (info.action === "keepalive"){
        //Send a keepalive to the server to prevent the session from expiring
        var getUserInfoAction = {
            action: "keepalive"
        };
        sendToSocket(JSON.stringify(getUserInfoAction));
    }
}

function displayUserInfo(info){
    var content = document.getElementById("content");
    if (content.firstChild) {
        content.removeChild(content.firstChild);
    }
    var contentDiv = document.createElement("div");
    content.appendChild(contentDiv);
    var table = document.createElement("table");
    table.setAttribute("class","table");
    var tablebody = document.createElement("tbody");
    var tableContents = {
        "Full Name":info.displayname,
        "Email":info.mailnickname,
        "Employee ID":info.employeeid,
        "Password Last Changed":info.pwdlastset,
        "Password Set to Expire":info.passwordsettoexpire,
        "Days Before Password Expires":info.daysleft,
        "Last Login":info.lastlogon,
        "Last Bad Password":info.badpasswordtime,
        "Account Expiration Date":info.accountexpires,
        "Other Email":info.othermailbox,
        "Bad Password Count":info.badpwdcount,
        "Groups":info.memberof
    };
    for(var prop in tableContents) {
        var tr = document.createElement("tr");
        var th = document.createElement("th");
        th.appendChild(document.createTextNode(prop));
        var td = document.createElement("td");
        td.innerHTML = tableContents[prop];
        tr.appendChild(th);
        tr.appendChild(td);
        tablebody.appendChild(tr);
    }
    if(info.lockouttime !== "N/A" && info.lockouttime !== "0")
    {
        var tr = document.createElement("tr");
        var th = document.createElement("th");
        th.appendChild(document.createTextNode("Locked Status"));
        var td = document.createElement("td");
        td.appendChild(ubutton);
        td.setAttribute("id","unlockcell");
        td.appendChild(lockMsg);
        td.appendChild(ubutton);
        tr.appendChild(th);
        tr.appendChild(td);
        tablebody.appendChild(tr);
    }
    table.appendChild(tablebody);
    contentDiv.appendChild(table);
}
function sendToSocket(message) {
    if(!socket || (socket && socket.readyState === socket.CLOSED)) {
        console.log("Reconnecting");
        socket = new WebSocket("ws"+ (window.location.protocol === 'https:' ? 's' : '')+"://"+window.location.host+window.location.pathname+"actions");
        socket.onmessage = onMessage;
        socket.onopen = function() {
            tokenLogin();
            socket.send(message);
        };
    }
    else {
        socket.send(message);
    }
}
function formUnlock(){
    if (user) {
        var unlockUser = {
            action: "unlock",
            user: user
        };
        sendToSocket(JSON.stringify(unlockUser));
    }
}
function formLogin(){
    var form = document.getElementById("loginForm");
    var username = form.elements["Username"].value;
    var password = form.elements["Password"].value;
    document.getElementById("loginForm").reset();
    var LoginAction = {
        action: "login",
        username: username,
        password: password
    };
    sendToSocket(JSON.stringify(LoginAction));
    return false;
}
function tokenLogin() {
    var token = window.localStorage.getItem("token");
    if(token !== null && token.length !== 38) {
        var LoginAction = {
            action: "cachedlogin",
            token: token
        };
        sendToSocket(JSON.stringify(LoginAction));
    }
    else {
        document.getElementById("begin").style.display = '';
    }
}
function formGetUserInfo(){
    var form = document.getElementById("userinfoForm");
    user = form.elements["User"].value;
    document.getElementById("loginForm").style.display = "none";
    var getUserInfoAction = {
        action: "getuserinfo",
        user: user
    };
    sendToSocket(JSON.stringify(getUserInfoAction));
    return false;
}

function searchUsers(e){
    var form = document.getElementById("userinfoForm");
    if(e.keyCode === 13) {
        $('.typeahead').typeahead('close');
        formGetUserInfo(null);
    }
    user = form.elements["User"].value;
    var now = Date.now();
    
    if(user.length > 0) {
        var getUserInfoAction = {
            action: "suggestion",
            user: user,
            timestamp: now
        };
        sendToSocket(JSON.stringify(getUserInfoAction));
        //startTime = performance.now();
    }
    return false;
}
function init() {
    ubutton = document.createElement("button");
    ubutton.innerHTML = "Unlock";
    ubutton.setAttribute("id","unlockbutton");
    ubutton.setAttribute("class","btn btn-secondary bluebutton");
    ubutton.onclick = formUnlock;
    lockMsg = document.createTextNode("");
    userSuggestions = new Bloodhound({
        datumTokenizer: Bloodhound.tokenizers.whitespace,
        queryTokenizer: Bloodhound.tokenizers.whitespace,
    });
    
    // Initializing the typeahead
    $('.typeahead').typeahead({
        hint: true,
        highlight: true, /* Enable substring highlighting */
        minLength: 1 /* Specify minimum characters required for showing result */
    },
    {
        name: 'userSuggestions',
        source: userSuggestions,
        limit: 8
    });
    
    $('.typeahead').bind('typeahead:select', function(ev, suggestion) {
        formGetUserInfo();
    });

    document.getElementById("Userbox").onkeyup = searchUsers;
    socket = new WebSocket("ws"+ (window.location.protocol === 'https:' ? 's' : '')+"://"+window.location.host+window.location.pathname+"actions");
    socket.onmessage = onMessage;
    socket.onopen = tokenLogin;
    socket.onclose = function() {
        setTimeout(function() {
            socket = new WebSocket("ws"+ (window.location.protocol === 'https:' ? 's' : '')+"://"+window.location.host+window.location.pathname+"actions");
        },5000);
    };
}
window.onload = init;