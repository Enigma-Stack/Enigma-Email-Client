import React from "react";
import {
  BrowserRouter as Router,
  Route,
  Routes,
  useNavigate,
} from "react-router-dom";
import Page1 from "./Page1";
import Page2 from "./Page2";
import "./Pages.scss";
import frame from "./assets/Frame.png";
import xyz from "./assets/xyz.png";
import rocket from "./assets/rocket.png";
import net from "./assets/mailnet.png";

const Main = () => {
  let navigate = useNavigate();
  return (
    <div className="main">
      <div className="page11">
        {/* <div className="rocket-img"><img src={rocket}></img></div> */}
        <div className="upper-p">
          <div className="left-p">
            <div className="bottom">
              Unrivaled Security for Modern Communication
            </div>
            <div className="top">
              QuMail is the cutting-edge Quantum Secure Email Client Application
              developed by the Team Enigma for a very prestigious Organization,
              ISRO, integrating state-of-the-art Quantum Key Distribution (QKD)
              technology to redefine the security standards of email
              communication.
            </div>
          </div>
          <div className="right-p"></div>
        </div>
        <div className="lower-p">
          <div className="upp">
            QuMail leverages Quantum Key Distribution to provide unparalleled
            security against eavesdropping and data breaches, ensuring the
            confidentiality and integrity of your communications.
          </div>
          <div className="low">
            <button
              onClick={() => {
                navigate("/signup");
              }}
            >
              Get started
            </button>

            <div>Start experiencing the next level of secure communication by getting started with QuMail now.</div>
          </div>
        </div>
      </div>

      <div className="page2">
        <div className="upper">
          <div className="top">Features That Define QuMail </div>
          <div className="bottom">
            <div className="lf">
              <h1>Quantum Integration</h1>
              <h2>
                QuMail is at the forefront of security innovation, seamlessly
                embedding Quantum Key Distribution technology into the email
                communication process. Leveraging quantum principles, it
                provides a level of security that's practically unattainable
                with conventional encryption methods.
              </h2>
            </div>
            <div className="rg">
              <h1>End-to-End Encryption</h1>
              <h2>
                End-to-End Encryption Your privacy is paramount. QuMail employs
                robust end-to-end encryption, safeguarding your emails from
                unauthorized access and ensuring that only intended recipients
                can decipher the encrypted content.
              </h2>
            </div>
          </div>
        </div>
        <div className="lower">
          <div className="lf">
            <div className="left">Quantum Key Management</div>
            <div className="rf">
              Quantum Key Management Managing Quantum Keys has never been
              easier. QuMail integrates with our advanced Key Manager service,
              ensuring secure and efficient handling of Quantum Keys for
              encryption and decryption purposes, adding an extra layer of
              security to your communications.
            </div>
          </div>

          <div className="lf">
            <div className="left">Quantum Key Management</div>
            <div className="rf">
              Quantum Key Management Managing Quantum Keys has never been
              easier. QuMail integrates with our advanced Key Manager service,
              ensuring secure and efficient handling of Quantum Keys for
              encryption and decryption purposes, adding an extra layer of
              security to your communications.
            </div>
          </div>
        </div>
      </div>

      <div className="page3">
        <div className="upper">
          <div className="part act">
            <div className="head1">Why Choose QuMail</div>
          </div>
          <div className="part">
            <div className="head2">Unbreakable Quantum Encryption</div>
            <div className="head3">
              Traditional encryption methods are susceptible to modern cyber
              threats. QuMail's Quantum Security offers an unbreakable shield,
              ensuring your sensitive data remains confidential, even in the
              face of advanced attacks.
            </div>
          </div>
          <div className="part">
            <div className="head2">User-Friendly Interface</div>
            <div className="head3">
              User-Friendly Interface Designed with user experience in mind,
              QuMail presents a sleek and intuitive interface that facilitates
              easy navigation, making secure communication effortless for users
              of all levels of expert.ise.
            </div>
          </div>
        </div>
        <div className="lower">
          <div className="left">
            <div>
              <div className="h1">Guided User Experience</div>
              <br />

              <div className="h2">
                For users new to Quantum Security or advanced encryption, QuMail
                offers intuitive guides and tooltips. These help users
                understand the significance of Quantum Security and make
                informed decisions while using the application.
              </div>
              <br />
              <br />

              <div className="h2">
                QuMail's user-friendly interface is meticulously designed to
                empower users, making secure communication an intuitive and
                hassle-free experience. We've blended cutting-edge security with
                an elegant and easy-to-navigate design, ensuring that your focus
                remains on your communication, not on complexities.
              </div>
            </div>
          </div>
          <div className="right">
            <img src={frame}></img>
          </div>
        </div>
      </div>

      <div className="page4">
        <img src={xyz}></img>

        <div className="upper">
          <div className="part act">
            <div className="head1">
              Safeguarding Your Communications with QuMail
            </div>
          </div>

          <div className="part">
            <div className="head2">Quantum Key Distribution (QKD):</div>
            <div className="head3">
              QuMail pioneers the use of Quantum Key Distribution, generating
              virtually impenetrable Quantum Keys. This unbreakable encryption
              shields your communication from any unauthorized access.
            </div>
          </div>

          <div className="part">
            <div className="head2">End-to-End Encryption:</div>
            <div className="head3">
              Your privacy is our priority. QuMail ensures end-to-end
              encryption, guaranteeing that only intended recipients can access
              your emails and attachments.
            </div>
          </div>
        </div>

        <div className="lower">
          <div className="part">
            <div className="head2">Quantum Key Distribution (QKD):</div>
            <div className="head3">
              QuMail pioneers the use of Quantum Key Distribution, generating
              virtually impenetrable Quantum Keys. This unbreakable encryption
              shields your communication from any unauthorized access.
            </div>
          </div>

          <div className="part">
            <div className="head2">End-to-End Encryption:</div>
            <div className="head3">
              Your privacy is our priority. QuMail ensures end-to-end
              encryption, guaranteeing that only intended recipients can access
              your emails and attachments.
            </div>
          </div>
        </div>
      </div>

      <div className="page5"></div>
    </div>
  );
};

export default Main;
