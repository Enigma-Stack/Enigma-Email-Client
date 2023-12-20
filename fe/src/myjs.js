import axios from 'axios';
import base64 from 'base-64';

// Utility to generate a random key of a given length
const generateRandomKey = (length) => {
    let result = '';
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
};

// Encrypt the message and encode it to base64
const encryptToBase64 = (message) => {
    const messageBytes = new TextEncoder().encode(message);
    return base64.encode(messageBytes);
};

// Decrypt from base64 encoded message
const decryptFromBase64 = (base64Message) => {
    const bytes = base64.decode(base64Message);
    return new TextDecoder().decode(bytes);
};

// Encrypt message with OTP
const encryptWithOTP = (message, key) => {
    const base64Message = encryptToBase64(message);
    let encryptedMessage = '';
    for (let i = 0; i < base64Message.length; i++) {
        const messageCharCode = base64Message.charCodeAt(i);
        const keyCharCode = key.charCodeAt(i % key.length);
        encryptedMessage += String.fromCharCode((messageCharCode + keyCharCode) % 256);
    }
    return encryptedMessage;
};

// Decrypt message with OTP
const decryptWithOTP = (encryptedMessage, key) => {
    let base64Message = '';
    for (let i = 0; i < encryptedMessage.length; i++) {
        const encryptedCharCode = encryptedMessage.charCodeAt(i);
        const keyCharCode = key.charCodeAt(i % key.length);
        base64Message += String.fromCharCode((encryptedCharCode - keyCharCode + 256) % 256);
    }
    return decryptFromBase64(base64Message);
};
  
  