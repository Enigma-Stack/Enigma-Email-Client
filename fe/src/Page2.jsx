import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import "./Pages.scss";
import net from "./assets/mailnet.png";
import rocket from "./assets/rocket.png";
import axios from "axios";
import { useEffect, useState, useRef } from "react";
import DOMPurify from "dompurify";
import base64 from "base-64";
import CryptoJS from "crypto-js";
import jsonData from "./assets/aes_keys.json";

const Page2 = () => {
  const hasRun = useRef(false);
  const [recipients, setRecipients] = useState([""]);
  const [newR, setNewR] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [attachments, setAttachments] = useState([]);
  const [mailPop, setMailPop] = useState(false);
  const [attach, setAttach] = useState([]);
  const [mid, setMid] = useState("");
  const [message, setMessage] = useState("");
  const [mes, setMes] = useState("");
  const [det, setDet] = useState([]);
  const [view, setView] = useState(true);
  const [opt, setOpt] = useState(0);

  const [tab, setTab] = useState(0);

  const [mail, setMail] = useState([
    {
      from: "Ishita",
      date: "4.00 P.M.",
      subject: "Security in post quantum era",
    },
    {
      from: "Ishita",
      date: "4.00 P.M.",
      subject: "Quantum secure mails",
    },
  ]);

  const sendEncryptedEmail = async (event) => {
    event.preventDefault();
    try {
      const recipientList = recipients.split(",").map((email) => email.trim());
      if (recipientList.every((email) => validateEmail(email))) {
        const recipient = recipientList[0];

        const formData = new FormData();
        formData.append("to", recipientList[0]);
        formData.append("subject", subject);
        formData.append("body", body);
        formData.append("attachment", attachments[0]);

        formData.append("encryption_flag", "1"); // Flag for OTP encryption

        console.log(formData);

        try {
          const response = await axios.post(
            "http://127.0.0.1:8000/send_email",
            formData,
            {
              headers: {
                "Content-Type": "multipart/form-data",
              },
            }
          );

          console.log(response.data);
        } catch (error) {
          console.error("Error sending email:", error);
        }

        // let ecode= encodeTo64(body)
        // const { data: bodyKeyData } = await axios.get(
        // `http://192.168.11.42:5000/api/otp/get-otp-key/${recipient}/${ecode}`
        // );

        // const encryptedBody = encrypt(bodyKeyData.key, ecode);

        // Get OTP Key for the attachment (if present)
        // let encryptedAttachment, attachmentUuid;

        // if (attachments.length > 0) {
        // const { data: attachmentKeyData } = await axios.get(
        // `http://192.168.11.42:5000/api/otp/get-otp-key/${recipient}/${attachments[0].size}`
        // );
        // encryptedAttachment = encryptWithOTP(
        // attachments[0],
        // attachmentKeyData.key
        // );
        // attachmentUuid = attachmentKeyData.uuid;
        // }

        // Prepare the form data
        // const formData = new FormData();
        // formData.append("to", recipient);
        // formData.append("subject", subject);
        // formData.append("body", encryptedBody);
        // formData.append("bodyUuid", bodyKeyData.uuid);

        // formData.append("attachment", attachments[0], attachments[0].name);
        // formData.append("attachmentUuid", '');

        // formData.append("encryption", 1); // Flag for OTP encryption

        // // Send the encrypted email
        // await axios.post(
        // "http://192.168.11.42:5000/api/gmail/sendWithAttachment",
        // formData,
        // {
        // headers: {
        // "Content-Type": "multipart/form-data",
        // },
        // }
        // );
      }
    } catch (error) {
      console.error("Error in sending encrypted email:", error);
    }
  };

  const sendEncryptedEmail2 = async (event) => {
    event.preventDefault();
    try {
      const recipientList = recipients.split(",").map((email) => email.trim());
      if (recipientList.every((email) => validateEmail(email))) {
        const recipient = recipientList[0];

        const formData = new FormData();
        formData.append("to", recipientList[0]);
        formData.append("subject", subject);
        formData.append("body", body);
        formData.append("attachment", attachments[0]);

        formData.append("encryption_flag", "2"); // Flag for OTP encryption

        console.log(formData);

        try {
          const response = await axios.post(
            "http://127.0.0.1:8000/send_email",
            formData,
            {
              headers: {
                "Content-Type": "multipart/form-data",
              },
            }
          );

          console.log(response.data);
        } catch (error) {
          console.error("Error sending email:", error);
        }

        // let ecode= encodeTo64(body)
        // const { data: bodyKeyData } = await axios.get(
        // `http://192.168.11.42:5000/api/otp/get-otp-key/${recipient}/${ecode}`
        // );

        // const encryptedBody = encrypt(bodyKeyData.key, ecode);

        // Get OTP Key for the attachment (if present)
        // let encryptedAttachment, attachmentUuid;

        // if (attachments.length > 0) {
        // const { data: attachmentKeyData } = await axios.get(
        // `http://192.168.11.42:5000/api/otp/get-otp-key/${recipient}/${attachments[0].size}`
        // );
        // encryptedAttachment = encryptWithOTP(
        // attachments[0],
        // attachmentKeyData.key
        // );
        // attachmentUuid = attachmentKeyData.uuid;
        // }

        // Prepare the form data
        // const formData = new FormData();
        // formData.append("to", recipient);
        // formData.append("subject", subject);
        // formData.append("body", encryptedBody);
        // formData.append("bodyUuid", bodyKeyData.uuid);

        // formData.append("attachment", attachments[0], attachments[0].name);
        // formData.append("attachmentUuid", '');

        // formData.append("encryption", 1); // Flag for OTP encryption

        // // Send the encrypted email
        // await axios.post(
        // "http://192.168.11.42:5000/api/gmail/sendWithAttachment",
        // formData,
        // {
        // headers: {
        // "Content-Type": "multipart/form-data",
        // },
        // }
        // );
      }
    } catch (error) {
      console.error("Error in sending encrypted email:", error);
    }
  };

  // useEffect hook
  useEffect(() => {
    if (!hasRun.current) {
      fetchEmails();

      hasRun.current = true;
    }
  }, []);

  useEffect(() => {
    // Sanitize the HTML content
    const cleanHtml = DOMPurify.sanitize(message);
    setMes(cleanHtml);
  }, [message]);

  useEffect(() => {
    // Sanitize the HTML content

    const fetchOpt = async () => {
      console.log("heee??");

      try {
        let emails = [];

        if (opt === 0) {
          console.log(0);
          emails = await axios.get("http://127.0.0.1:8000/emails");
          console.log("Paginated email:", emails.data);
        } else {
          console.log(1);
          emails = await axios.get(
            "http://192.168.11.42:5000/api/gmail/sent-emails"
          );
          console.log("Sent email:", emails.data);
        }

        let emailList = emails.data.map((item) => item);
        setMail(emailList.reverse());
      } catch (error) {
        console.error("Error fetching emails:", error);
      }
    };

    fetchOpt();
  }, [opt]);

  //encryption functions

  //email-functions

  const fetchEmails = async () => {
    try {
      // Fetch inbox emails

      const emails = await axios.get("http://127.0.0.1:8000/emails");
      console.log("Paginated email:", emails);

      let email = [];
      emails.data.map((item) => {
        email.push(item);
      });

      setMail(email.reverse());
      console.log(mail);

      // Fetch sent emails
      // const sentResponse = await axios.get(
      // "http://192.168.11.42:5000/api/gmail/sent"
      // );
      // console.log("Sent Emails:", sentResponse.data);
    } catch (error) {
      console.error("Error fetching emails:", error);
    }
  };

  useEffect(() => {
    const fetchEma = async () => {
      try {
        let emails = [];

        if (opt === 0) {
          emails = await axios.get("http://127.0.0.1:8000/emails");
          console.log("Paginated email:", emails.data);
        } else {
          emails = await axios.get(
            "http://192.168.11.42:5000/api/gmail/sent-emails"
          );
          console.log("Sent email:", emails.data);
        }

        let emailList = emails.data.map((item) => item);
        setMail(emailList.reverse());
      } catch (error) {
        console.error("Error fetching emails:", error);
      }
    };

    // Call the function for the first time
    fetchEma();

    // Set up the interval
    const intervalId = setInterval(() => {
      fetchEma();
    }, 50000); // 10000 milliseconds = 10 seconds

    // Clear the interval on unmount
    return () => clearInterval(intervalId);
  }, []); // Empty dependency array ensures this runs once on mount and unmount

  const formatName = (from) => {
    const namePart = from.split("<")[0].trim();
    return namePart;
  };

  const formatDate = (dateString) => {
    const emailDate = new Date(dateString);
    const currentDate = new Date();

    if (emailDate.toDateString() === currentDate.toDateString()) {
      // If the email is from today, return only the time
      return emailDate.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
      });
    } else {
      // Otherwise, return the date in a readable format
      return emailDate.toLocaleDateString();
    }
  };

  const isUnread = (labelIds) => {
    return labelIds && labelIds.includes("UNREAD");
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const recipientList = recipients.split(",").map((email) => email.trim());
    if (recipientList.every((email) => validateEmail(email))) {
      // All emails are valid, proceed with submission
      console.log({ recipientList, subject, body, attachments });

      console.log(attachments);

      const formData = new FormData();
      formData.append("to", recipientList[0]);
      formData.append("subject", subject);
      formData.append("body", body);
      formData.append("attachment", attachments[0]);

      formData.append("encryption_flag", "0"); // Flag for OTP encryption

      console.log(formData);

      try {
        const response = await axios.post(
          "http://127.0.0.1:8000/send_email",
          formData,
          {
            headers: {
              "Content-Type": "multipart/form-data",
            },
          }
        );

        console.log(response.data);
      } catch (error) {
        console.error("Error sending email:", error);
      }
      // Handle form submission here
    } else {
      // Handle invalid email addresses
      alert("One or more email addresses are invalid.");
    }
  };

  const hadleDowload = async (att) => {
    console.log(att);
    console.log(mid);
    try {
      const response = await axios.get(
        `http://192.168.11.42:5000/api/gmail/attachment/${mid}/${att.attachmentId}`,
        {
          responseType: "blob", // Important to handle binary data correctly
        }
      );

      const contentDisposition = response.headers["content-disposition"];
      let filename = att.filename;
      if (contentDisposition) {
        const matches = /filename="([^"]+)"/.exec(contentDisposition);
        if (matches && matches[1]) {
          filename = matches[1];
        }
      }

      // Create a URL from the blob
      const url = window.URL.createObjectURL(new Blob([response.data]));

      // Create a temporary anchor element and trigger download
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();

      // Cleanup
      window.URL.revokeObjectURL(url);
      link.remove();
    } catch (error) {
      console.error("Error downloading file: ", error);
    }
  };

  const handleAttachmentChange = (event) => {
    setAttachments([...event.target.files]);
  };

  const sendEmail = (event) => {
    if (tab === 0) {
      handleSubmit(event);
    } else if (tab === 1) {
      sendEncryptedEmail(event);
    } else if (tab === 2) {
      sendEncryptedEmail2(event);
    } else {
    }
  };

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  function hashAndProcess(inputString) {
    // Hash the input using SHA-256
    const hash = CryptoJS.SHA256(inputString.toLowerCase()).toString(
      CryptoJS.enc.Hex
    );

    // Take the first 4 characters of the hash
    const firstFourChars = hash.substring(0, 4);

    // Convert the 4 characters into an integer
    const intValue = parseInt(firstFourChars, 16);

    // Modulo 100
    const result = intValue % 100;

    return result;
  }

  const hadleView = async (id) => {
    console.log("here");
    try {
      //console.log(emails);
      console.log(id);
      console.log(id.encryption.flag);

      if (id.encryption.flag === 0) {
        //console.log("email:", emails.data);
        console.log("entered 0");

        setAttach(id.attachments);
        //setMid(emails.data.id);
        setDet(id);
        setMessage(id.body);

        setView(false);
      } else if (id.encryption.flag === 1) {
        try {
          // let bodyUuid = "d4e9a78f-67ad-4aaa-b190-5a2770a89613";
          // let attachmentUuid = "d4e9a78f-67ad-4aaa-b190-5a2770a89613"
          // let key =
          //   "8725233a49f5c395feeec9060fbb56c8d0aa7068cdf6a22efb81c34ef211851a";
         let x_body_uuid = id["headers"]["X-Body-UUID"]//.get("X-Body-UUID", "Default-UUID-if-not-found");

          let bodyyy = {
            bodyUuid: x_body_uuid,
            flag: 1,
            body: id.body,
          };
          console.log("hereh", bodyyy);
          try {
            const response = await axios.post(
              "http://127.0.0.1:8000/decrypt",
              bodyyy
            );

            console.log(response.data);

            setAttach(id.attachments);
            //setMid(emails.data.id);
            setDet(id);
            setMessage(response.data.message);

            setView(false);
          } catch (error) {
            console.error("Error sending email:", error);
          }

          // // Fetch the OTP key using the email UUID
          // let params = {
          // userEmail: emails.data.headers.to,
          // uuid: emails.data.encryption.uuid,
          // };

          // console.log(params);

          // // const { data } = await axios.get(
          // // `http://192.168.11.42:5000/api/otp/get-otp-open/${emails.data.encryption.bodyUuid}/${params.userEmail}`
          // // );

          // console.log(data.key);

          // // Decrypt the email body
          // const decryptedEmailBody = decrypt(
          // emails.data.snippet,
          // data.key
          // );
          // console.log("here");
          // console.log(decryptedEmailBody);

          // setMessage(decodeFrom64(decryptedEmailBody));
          // setMid(emails.data.id);
          // setDet(emails.data.headers);

          // const { data2 } = await axios.get(
          // `http://192.168.11.42:5000/api/otp/get-otp-open/${emails.data.encryption.attachmentUuid}/${params.userEmail}`
          // );

          // console.log(data2.key);

          // Decrypt the attachment

          // Convert the decrypted attachment to a Blob

          // setAttach(emails.data.attachments);

          // Set the original filename for the download link
          //setFilename(originalFilename);
        } catch (error) {
          console.error("Error during decryption:", error);
        }
      } else if (id.encryption.flag === 2) {
        try {
          let bodyUuid = "d4e9a78f-67ad-4aaa-b190-5a2770a89613";
          // let attachmentUuid = "d4e9a78f-67ad-4aaa-b190-5a2770a89613"
          let key =
            "8725233a49f5c395feeec9060fbb56c8d0aa7068cdf6a22efb81c34ef211851a";

          console.log(id.encryption);

          let x_body_uuid = id["headers"]["X-Body-UUID"]//.get("X-Body-UUID", "Default-UUID-if-not-found");

          let bodyyy = {
            bodyUuid: x_body_uuid,
            flag: 2,
            body: id.body,
          };
          try {
            const response = await axios.post(
              "http://127.0.0.1:8000/decrypt",
              bodyyy
            );

            console.log(response.data);

            setAttach(id.attachments);
            //setMid(emails.data.id);
            setDet(id);
            setMessage(response.data.message);

            setView(false);
          } catch (error) {
            console.error("Error sending email:", error);
          }

          // let params = {
          // userEmail: emails.data.headers.to,
          // uuid: emails.data.encryption.uuid,
          // };

          // console.log(params);

          // // const { data } = await axios.get(
          // // `http://192.168.11.42:5000/api/otp/get-otp-open/${emails.data.encryption.bodyUuid}/${params.userEmail}`
          // // );

          // console.log(data.key);

          // // Decrypt the email body
          // const decryptedEmailBody = decrypt(
          // emails.data.snippet,
          // data.key
          // );
          // console.log("here");
          // console.log(decryptedEmailBody);

          // setMessage(decodeFrom64(decryptedEmailBody));
          // setMid(emails.data.id);
          // setDet(emails.data.headers);

          // const { data2 } = await axios.get(
          // `http://192.168.11.42:5000/api/otp/get-otp-open/${emails.data.encryption.attachmentUuid}/${params.userEmail}`
          // );

          // console.log(data2.key);

          // Decrypt the attachment

          // Convert the decrypted attachment to a Blob

          // setAttach(emails.data.attachments);

          // Set the original filename for the download link
          //setFilename(originalFilename);
        } catch (error) {
          console.error("Error during decryption:", error);
        }
      }

      //let emailList = emails.data.messages.map((item) => item);
      //setMail(emailList);
    } catch (error) {
      console.error("Error fetching email:", error);
    }

    setView(false);
  };

  return (
    <div className="main">
      <div className="page12">
        {mailPop && (
          <div className="overlay">
            <div className="mail-box">
              <div className="top">
                <div className="le">New Message</div>
                <div
                  className="reft"
                  onClick={() => {
                    setMailPop(false);
                  }}
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    fill="black"
                    viewBox="0 0 30 30"
                    width="15px"
                    height="15px"
                  >
                    <path d="M25.707,6.293c-0.195-0.195-1.805-1.805-2-2c-0.391-0.391-1.024-0.391-1.414,0c-0.195,0.195-17.805,17.805-18,18c-0.391,0.391-0.391,1.024,0,1.414c0.279,0.279,1.721,1.721,2,2c0.391,0.391,1.024,0.391,1.414,0c0.195-0.195,17.805-17.805,18-18C26.098,7.317,26.098,6.683,25.707,6.293z" />
                    <path d="M23.707,25.707c0.195-0.195,1.805-1.805,2-2c0.391-0.391,0.391-1.024,0-1.414c-0.195-0.195-17.805-17.805-18-18c-0.391-0.391-1.024-0.391-1.414,0c-0.279,0.279-1.721,1.721-2,2c-0.391,0.391-0.391,1.024,0,1.414c0.195,0.195,17.805,17.805,18,18C22.683,26.098,23.317,26.098,23.707,25.707z" />
                  </svg>
                </div>
              </div>
              <form className="email-compose" onSubmit={sendEmail}>
                <input
                  type="text"
                  value={recipients}
                  onChange={(e) => setRecipients(e.target.value)}
                  placeholder="To: (comma-separated email ids)"
                  className="email-to"
                />
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="Subject:"
                />
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder="Your message here..."
                />
                <input type="file" onChange={handleAttachmentChange} multiple />

                <div className="but">
                  <div
                    className={tab === 0 ? "iact a" : "iact"}
                    onClick={() => {
                      setTab(0);
                    }}
                  >
                    Default
                  </div>
                  <div
                    className={tab === 1 ? "iact a" : "iact"}
                    onClick={() => {
                      setTab(1);
                    }}
                  >
                    OTP
                  </div>
                  <div
                    className={tab === 2 ? "iact a" : "iact"}
                    onClick={() => {
                      setTab(2);
                    }}
                  >
                    AES
                  </div>
                  <button className="acti" type="submit">
                    Send
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
        <div className="top-bar">QMail</div>
        <div className="middle-bar">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="13"
            height="13"
            viewBox="0 0 13 13"
            fill="none"
          >
            <path
              d="M6.5 1V12"
              stroke="#2563EB"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <path
              d="M1 6.5H12"
              stroke="#2563EB"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
          <div
            onClick={() => {
              setMailPop(true);
            }}
          >
            Compose
          </div>
        </div>
        <div className="lower-bar">
          <div className="left">
            <div
              className={opt === 0 ? "obj act" : "obj"}
              onClick={() => {
                setOpt(0);
              }}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="19"
                height="15"
                viewBox="0 0 19 15"
                fill="none"
              >
                <path
                  d="M14.9469 1.90188L17.75 7.5V12.375C17.75 12.806 17.5788 13.2193 17.274 13.524C16.9693 13.8288 16.556 14 16.125 14H3.125C2.69402 14 2.2807 13.8288 1.97595 13.524C1.67121 13.2193 1.5 12.806 1.5 12.375V7.5L4.30313 1.90188C4.43766 1.63114 4.64505 1.4033 4.90197 1.24398C5.1589 1.08465 5.45518 1.00016 5.7575 1H13.4925C13.7948 1.00016 14.0911 1.08465 14.348 1.24398C14.605 1.4033 14.8123 1.63114 14.9469 1.90188Z"
                  stroke="#2563EB"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              <div
              // onClick={() => {
              // setMailPop(true);
              // }}
              >
                Inbox
              </div>
            </div>

            <div
              className={opt === 1 ? "obj act" : "obj"}
              onClick={() => {
                setOpt(1);
              }}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="21"
                height="16"
                viewBox="0 0 21 16"
                fill="none"
              >
                <path
                  d="M20 8L0.999999 15L5 8L1 0.999999L20 8Z"
                  stroke="#2563EB"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <line x1="6.5" y1="8" x2="13.5" y2="8" stroke="#2563EB" />
              </svg>
              <div>Sent</div>
            </div>
          </div>

          <div className="right">
            {view &&
              mail.map((item, index) => {
                return (
                  <div
                    key={index}
                    className={`item 
 `}
                    onClick={() => {
                      console.log(item);
                      hadleView(item);
                    }}
                  >
                    <div className="from">{formatName(item.from)}</div>
                    <div className="subject">{item.subject}</div>
                    <div className="time">{formatDate(item.date)}</div>
                  </div>
                );
              })}

            {!view && (
              <>
                <div
                  className="author-top"
                  onClick={() => {
                    setView(true);
                  }}
                >
                  <svg
                    width="10"
                    height="15"
                    viewBox="0 0 10 15"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path d="M8 1L2 7L8 13" stroke="#2563eb" stroke-width="2" />
                  </svg>
                </div>
                <div className="sub">
                  <div className="left">{det.subject}</div>
                  <div className="right">
                    {new Date(det.date).toLocaleTimeString("en-US", {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}{" "}
                  </div>{" "}
                </div>
                <div className="det">
                  <div>From : {det.from}</div>
                </div>

                <div className="det">
                  <div>
                    To : {det.to} {det.bcc ? " BCC : " + det.bcc : ""}{" "}
                    {det.cc ? " CC : " + det.cc : ""}
                  </div>
                </div>
                <div
                  className="mail-con"
                  dangerouslySetInnerHTML={{ __html: mes }}
                />

                <div className="attach">
                  {attach?.map((att) => {
                    return (
                      <div className="file">
                        <div
                          className="thumb"
                          onClick={() => {
                            hadleDowload(att);
                          }}
                        ></div>
                        {att.filename}
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Page2;
