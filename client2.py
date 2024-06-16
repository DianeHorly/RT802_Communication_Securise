import json
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import os
import time
from cryptography.hazmat.primitives.asymmetric import padding

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
    # genere une clé symétrique
    session_key = os.urandom(32)  # AES-256 

    # charge le certificat du vendeur
    with open("vendeur_certificate.pem", "r") as f:
        certificate = f.read()
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    client_public_key = cert.public_key()

    # Encrypt la clé de session avec la clé publique du vendeur
    encrypted_session_key = client_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # envoi la clé de session encrypté au vendeur
    client.publish("vehicle/session_key", json.dumps({"encrypted_session_key": encrypted_session_key.hex()}))
    print("Encrypted session key sent to the client.")

def isRevoke():
    with open("vendeur_certificate.pem", "r") as f:
        certificate = f.read()
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    serial_number = cert.serial_number
    client.publish("vehicle", json.dumps({"action": "check_revocation", "serial_number": serial_number}))

# Callback pour la connexion MQTT
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("vehicle")
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
                print("Le certificat n'est pas valide")
        time.sleep(2)
        isRevoke()
    elif msg.topic == "vehicle":
        revoked = message.get("revoked")
        if revoked is not None:
            if revoked:
                print("Le certificat est révoqué.")
            else:
                print("Le certificat n'est pas révoqué.")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("194.57.103.203", 1883, 60)
client.loop_forever()