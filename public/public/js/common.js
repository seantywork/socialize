
ws = {}

MESSAGE_FORMAT = {

    command: "",
    data: ""

}

resumeToken = ""
resumeCount = 0
resumeThreshold = 10

step = 0


let newUI = `

<div class='row'>
    <div class='input-field col s12'>
        <input class='validate' name='command' id='command'/>
        <label for='command'>Enter command</label>
    </div>
</div>

<div class='row'>
    <div class='input-field col s12'>
        <input class='validate' name='data' id='data'/>
        <label for='data'>Enter data</label>
    </div>
</div>

<br/>
<div class='row'>
    <input type="button" value="Send" onclick="sendFromUI()">


`

function signin(){


    let email = document.getElementById("email").value

    let password = document.getElementById("password").value

    if(email == ""){

        alert("email is empty")

        return 
    }

    if(password == ""){

        alert("password is empty")
        
        return 
    }


    ws = new WebSocket("/front")


    let cred = email + ":" + password

    ws.onopen = function(evt){

        ws.send(JSON.stringify({command: "auth", data: cred}))
    
    }
    
    ws.onclose = function(evt) {
        alert("connection to server has closed")
    }
    
    ws.onmessage = function(evt) {

        let msg = JSON.parse(evt.data)
    
        if (!msg) {
 
            alert("failed to parse msg")

            return
        }


        let data = msg.data

        if(step == 0){

            if(msg.status != "success") {

                alert("failed to auth")

                return
            }
   
            resumeToken = data

            
            sendMessage("auth", data)

            step = 1

            return
        }
        

        if(step == 1){

            if(msg.status != "success") {

                if(resumeToken != ""){

                    if(resumeCount > resumeThreshold){

                        alert("failed to connect")

                        return
                    }

                    sendMessage("auth", resumeToken)

                    resumeCount += 1
                    return 
                }

                alert("failed to connect")

                return
            }

            let adminpage = document.getElementById("socialize-admin")

            adminpage.innerHTML = newUI

            step = 2

            return
        }

        if(msg.status == "success") {

            alert("got data: \n" + msg.data)

            return

        } else {

            alert("failed: " + msg.status)
        }

        return

    }

    ws.onerror = function(evt) {
        console.log("error: " + evt.data)
    }

}

function sendFromUI(){

    let cmd = document.getElementById("command").value

    let msg = document.getElementById("data").value
    
    sendMessage(cmd, msg)

}

function sendMessage(cmd, msg){

    let req = JSON.parse(JSON.stringify(MESSAGE_FORMAT))

    req.command = cmd
    req.data = msg

    ws.send(JSON.stringify(req))

}

