import requests
from fastapi import APIRouter, Body, FastAPI
from fastapi import HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi import UploadFile, File, Form
from aes.body import aes_encrypt, aes_decrypt
import shutil
import os
import imap
import email_sender
import otp
import json

EMAIL = ""
PASSWORD = ""
PORT = ""
HOST = ""
HOST_IMAP = ""
PORT_IMAP = ""

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter()


@router.get("/test")
def test():
    return {"test": "ok"}


@router.put("/creds")
def get_creds(payload=Body(...)):
    try:
        global EMAIL, PASSWORD, PORT, HOST, HOST_IMAP, PORT_IMAP
        EMAIL = payload["email_id"]
        PASSWORD = payload["password"]
        PORT = payload["port"]
        HOST = payload["host"]
        HOST_IMAP = payload["host_imap"]
        return {
            "email": EMAIL,
            "password": PASSWORD,
            "port": PORT,
            "host": HOST,
            "host_imap": HOST_IMAP,
            "port_imap": PORT_IMAP
        }
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing key in payload: {e}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.get("/emails")
def get_inbox():
    try:
        print("inside get inbox")
        mails = imap.fetch_emails(EMAIL, PASSWORD, HOST_IMAP)
        return [email.to_dict() for email in mails]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.get("/sent_email")
def get_email(payload=Body(...)):
    try:
        pass
    except Exception as e:
        return {"status": "not ok", "error": str(e)}


@app.post("/send_email")
async def post_email(
    to: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    attachment: UploadFile = File(None),
    encryption_flag: str = Form(...),
):
    try:
        # Save attachment to 'uploads' directory
        print("enc",encryption_flag)
        file_location = None
        if attachment:
            file_location = f"uploads/{attachment.filename}"
            with open(file_location, "wb") as file_object:
                shutil.copyfileobj(attachment.file, file_object)
                
        bodyUuid = []
        attachmentUuid = []

        if encryption_flag == "0":
            pass
        # Process the email body based on encryption flag
        if encryption_flag == "1":
            body = otp.encode_to_64(body)
            response = requests.get(f"http://13.53.41.219/genkey?length={len(body)}")
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="Key generation API call failed")

            key_info = response.json()
            print(f"Content of key_info: {key_info}")

            # Handling the key_info list of lists
            if isinstance(key_info, list) and all(isinstance(item, list) and len(item) == 2 for item in key_info):
                bodyUuid, key_strings = zip(*key_info)  # Unpack the list of lists
                key = ''.join(key_strings)  # Concatenate the key strings
            else:
                raise HTTPException(status_code=500, detail="Invalid key info structure")
            print("hello")

            key_fin = key * (len(body) // len(key)) + key[:(len(body) % len(key))]
            encrypted_body = otp.encrypt(body, key_fin)
            body = encrypted_body


        elif encryption_flag == "2":
            # Request an AES key from the API
            response = requests.get("http://13.53.41.219/genkey?length=32")
            print("AES")
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="Key generation API call failed")

            key_info = response.json()  # Assuming this is a list of {'uuid': '32-byte-key-string'}
            
            # Handling the key_info list of lists
            print(response)
            if isinstance(key_info, list) and all(isinstance(item, list) and len(item) == 2 for item in key_info):
                bodyUuid, key_strings = zip(*key_info)  # Unpack the list of lists
                key = ''.join(key_strings)  # Concatenate the key strings
            else:
                raise HTTPException(status_code=500, detail="Invalid key info structure")
            print("hellop", key)
            aes_key = key#''.join([item['key'] for item in key_info])

            # Encrypt the body
            print(type(aes_key), aes_key, "klklk")
            encrypted_body = aes_encrypt(body, aes_key)
            body = encrypted_body  # The body is now encrypted
            print(body)

            # # Encrypt the attachment
            # if attachment:
            #     file_location = f"uploads/{attachment.filename}"
            #     with open(file_location, "wb") as file_object:
            #         shutil.copyfileobj(attachment.file, file_object)
                
            #     with open(file_location, 'rb') as file:
            #         attachment_data = file.read()
            #         encrypted_attachment = aes_encrypt(attachment_data, aes_key)
            #         with open(file_location, "wb") as encrypted_file:
            #             encrypted_file.write(bytes.fromhex(encrypted_attachment))  # Write the encrypted data

            # Store the AES key for decryption, using bodyUuid as the identifier

            # # bodyUuid = [item['uuid'] for item in key_info]
            # print("Type of bodyUuid:", type(bodyUuid))
            # print("bodyUuid content:", bodyUuid)

            # try:
            #     with open("deleted_keys.json", "r") as file:
            #         # Load existing data
            #         existing_data = json.load(file)
            # except FileNotFoundError:
            #     # If the file does not exist, create an empty dictionary
            #     existing_data = {}

            # # Update with the new key
            # print("bodyUuid", bodyUuid)
            # existing_data[bodyUuid[0]] = aes_key

            # # Write the updated data back to the        
            # with open("deleted_keys.json", "w") as file:
            #     json.dump(existing_data, file, indent=4)  # Using indent for better readability


        attachmentUuid = '[]'
        # Send the email
        email_sender.send_email_with_attachment(
            to,
            bodyUuid,
            attachmentUuid,
            file_location,
            body,
            subject,
            encryption_flag,
            # to=to, subject=subject, body=body,
            # attachment_file_path=file_location,
            # attachment_mime_type=attachment.content_type if attachment else None,
            # attachment_file_name=attachment.filename if attachment else None,
        )

        # Optional: Delete the file after sending the email
        if file_location and os.path.exists(file_location):
            os.remove(file_location)

        return {"status": "ok"}
    except Exception as e:
        # Clean up if there's an error
        if file_location and os.path.exists(file_location):
            os.remove(file_location)
        raise HTTPException(status_code=500, detail=str(e))


# @router.post('/send_email')
# def post_email(payload=Body(...)):
#     try:
#         if payload['flag'] == 0:
#             email_sender.send_email_with_attachment(payload)
#         elif payload['flag'] == 1:
#             body = payload.get('body', '')
#             body = otp.encrypt_to_64(body)
#             key = payload.get('key','')
#             key_fin = key*(len(body)//len(key)) + key[len(body)%len(key)]
#             encrypted_body = otp.encrypt(body,key_fin)
#             payload['body'] = encrypted_body
#             email_sender.send_email_with_attachment(payload)
#         elif payload['flag'] == 2:
#             # nimish kar aes
#             pass
#         return {'status':'ok'}
#     except Exception as e:
#         return {'status': 'not ok', 'error': str(e)}


@router.post("/decrypt")
def decrypt_email(payload=Body(...)):
    print("flag: ", payload["flag"])
    try:
        if payload["flag"] == 0:
            return {"message": payload.get("body", "")}

        elif payload["flag"] == 1 or payload["flag"] == 2:
            body = payload.get("body", "")
            uuids = payload.get("bodyUuid")
            list_body_uuids = uuids.split(',')
            list_body_uuids[0] = list_body_uuids[0][1:]
            list_body_uuids[-1] = list_body_uuids[-1][:-1]
            print("UUIDs:", list_body_uuids)

            # Make an API call to retrieve the keys
            response = requests.post("http://13.53.41.219/getkey", json={"uuids": list_body_uuids})
            print("Response:", response)
            
            if response.status_code == 200 and response.json():
                keys = response.json()
                # Update existing data
                try:
                    with open("deleted_keys.json", "r") as file:
                        existing_data = json.load(file)
                except FileNotFoundError:
                    existing_data = {}

                for uuid, key in zip(list_body_uuids, keys):
                    existing_data[uuid] = key

                with open("deleted_keys.json", "w") as file:
                    json.dump(existing_data, file, indent=4)
            else:
                # Fallback to check in deleted_keys.json if API call failed or returned null
                with open("deleted_keys.json", "r") as file:
                    stored_keys = json.load(file)
                    keys = [stored_keys.get(uuid) for uuid in list_body_uuids if uuid in stored_keys]

            key = ''.join(keys)  # Concatenate all keys
            print("Concatenated Key:", key)

            # Decryption logic based on the flag
            if payload["flag"] == 1:
                # Adjust key length as needed for OTP decryption
                key_fin = key * (len(body) // len(key)) + key[:(len(body) % len(key))]
                print("KEYFIN", key_fin)
                message_64 = otp.decrypt(body, key_fin)
                message = otp.decode_from_64(message_64)
                return {"message": message}

            elif payload["flag"] == 2:
                decrypted_body = aes_decrypt(body, key)
                return {"message": decrypted_body}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )



app.include_router(router)
