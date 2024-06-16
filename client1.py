import json
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def load_ca_certificate():
    with open("ca_certificate.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_cert

ca_cert = load_ca_certificate()

def verify_certificate(client_cert_pem):
    client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))
    # Vérifier que le certificat du vendeur est signé par la CA
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm
        )
        print("Le certificat du client est valide et signé par la CA.")
        return client_cert
    except Exception as e:
        print(f"Le certificat du client est invalide: {e}")
        return None

def send_session_key():
    # Generate a random session key
    session_key = os.urandom(32)  # AES-256 key

    # Load client's public key from the certificate
    with open("vendeur_certificate.pem", "r") as f:
        certificate = f.read()
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    client_public_key = cert.public_key()

    # Encrypt the session key with the client's public key
    encrypted_session_key = client_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send the encrypted session key to the client
    client.publish("vehicle/session_key", json.dumps({"encrypted_session_key": encrypted_session_key.hex()}))
    print("Encrypted session key sent to the client.")

# Callback pour la connexion MQTT
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("vehicle")
    #client.publish("vehicle", json.dumps({"action": "issue", "csr": csr}))
    client.subscribe("vehicle/achat")
    client.publish("vehicle/achat", json.dumps({"action": "get_certificate"}))
    
# Callback pour la réception des messages MQTT
def on_message(client, userdata, msg):
    message = json.loads(msg.payload)
    if msg.topic == "vehicle/achat":
        certificate = message.get("certificate")
        if certificate:
            verified_cert = verify_certificate(certificate)
            if verified_cert:
                print("Le certificat est valide, l'achat peut se faire")
                send_session_key()
            else:
                print("Le certficat n'est pas valide")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("194.57.103.203", 1883, 60)
client.loop_forever()