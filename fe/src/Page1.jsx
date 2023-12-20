import React from "react";
import {
    BrowserRouter as Router,
    Route,
    Routes,
    useNavigate,
} from "react-router-dom";
import "./Pages.scss";
import net from "./assets/mailnet.png";
import rocket from "./assets/rocket.png";
//import { google } from "googleapis";
import { useState, useEffect } from "react";
import axios from "axios";
import mil from "./assets/mil.png";

const CLIENT_ID =
    "747754888091-s9g09uhebkv3kvuhp0ahk51gg1n0b0ua.apps.googleusercontent.com";
const API_KEY = "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";
const DISCOVERY_DOC =
    "https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest";
const SCOPES = "https://www.googleapis.com/auth/gmail.readonly";
const REDIRECT_URI = "https://developers.google.com/oauthplayground";

// const signup = async ()=>{
//   console.log("signing up");

// }

const Page1 = () => {
    const [isSignedIn, setIsSignedIn] = useState(false);
    const [labels, setLabels] = useState([]);
    const [error, setError] = useState("");
    const [name, setName] = useState("");
    const [pass, setPass] = useState("");
    const [port, setPort] = useState(0);
    const [host, setHost] = useState("");
    const [host_imap, setHost_imap] = useState("");
    let navigate = useNavigate();

    //   useEffect(() => {
    //     const url = new URL(window.location.href);
    //     console.log("here")
    //     const authorizationCode = url.searchParams.get("code");

    //     if (authorizationCode) {
    //         // Send the code to the server
    //         fetch('http://192.168.11.42:5000/exchange-code', {
    //             method: 'POST',
    //             headers: { 'Content-Type': 'application/json' },
    //             body: JSON.stringify({ code: authorizationCode })
    //         })
    //         .then(response => response.json())
    //         .then(data => {
    //             // Handle tokens here
    //             console.log(data);
    //         })
    //         .catch(error => {
    //             console.error('Error:', error);
    //         });
    //     }
    // }, [window.location.href]);

    const handleAuthClick = async () => {
        let body = {
            email_id: name,
            password: pass,
            host_imap: host_imap,
            port: port,
            host: host,
        };

        let bodyy = {
            "email_id": "20cs3011@rgipt.ac.in",
            "password": "nskd kizg vxba plqs",
            "port": "465",
            "host": "smtp.gmail.com",
            "host_imap": "imap.gmail.com"
        }
        // let bodyy = {
        //     "email_id": "raj.aryaman@zohomail.in",
        //     "password": "Aryaman@0816",
        //     "port": "993",
        //     "host": "smtp.zoho.com",
        //     "host_imap": "imap.zoho.com"
        // }
        // let bodyy = {
        //     "email_id": "dastitwa@hotmail.com",
        //     "password": "astitwa123",
        //     "port": "993",
        //     "host": "smtp.rediffmail.com",
        //     "host_imap": "imap-mail.outlook.com"
        // }
        const emails = await axios.put("http://127.0.0.1:8000/creds", body);

        console.log(emails)

        navigate("/mail");

        //console.log("here");
        // window.location.href = "http://192.168.11.42:5000/auth/google";
    };

    const handleSignoutClick = async () => {
        try {
            await axios.post("http://192.168.11.42:5000/auth/signout");
            setIsSignedIn(false);
            setLabels([]);
        } catch (error) {
            console.error("Error signing out:", error);
        }
    };

    return (
        <div className="main">
            <div className="page1">
                {/* <div className="rocket-img">
          <img src={rocket}></img>
        </div> */}

                <div className="mail-box">
                    <div className="box">
                        <img src={mil}></img>
                    </div>
                    <p>A step ahead towards security</p>
                    {error && <p>Error: {error}</p>}

                    <input
                        type="text"
                        placeholder="Email"
                        value={name}
                        onChange={(e) => {
                            setName(e.target.value);
                        }}
                    ></input>
                    <br />
                    <input
                        type="password"
                        placeholder="Password"
                        value={pass}
                        onChange={(e) => {
                            setPass(e.target.value);
                        }}
                    ></input>
                    <br />
                    <input
                        type="number"
                        placeholder="Port"
                        value={port}
                        onChange={(e) => {
                            setPort(e.target.value);
                        }}
                    ></input>
                    <br />
                    <input
                        type="text"
                        placeholder="SMTP Host"
                        value={host}
                        onChange={(e) => {
                            setHost(e.target.value);
                        }}
                    ></input>
                    <br />
                    <input
                        type="text"
                        placeholder="IMAP Host"
                        value={host_imap}
                        onChange={(e) => {
                            setHost_imap(e.target.value);
                        }}
                    ></input>
                    <br />

                    {!isSignedIn && (
                        <button onClick={handleAuthClick}>Authorize</button>
                    )}

                    {/* {isSignedIn && <button onClick={handleSignoutClick}>Sign Out</button>} */}
                </div>
                <div className="upper-p"></div>
                <div className="lower-p"></div>
            </div>
        </div>
    );
};

export default Page1;
