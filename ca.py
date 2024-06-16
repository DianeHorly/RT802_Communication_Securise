import json
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# Initialisation des paramètres de la CA
def generate_ca_certificate():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Ma CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ca.example.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key, hashes.SHA256())
    with open("ca_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption()))
    with open("ca_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    return private_key, cert

ca_private_key, ca_cert = generate_ca_certificate()
crl = set()

# Fonction pour émettre des certificats
def issue_certificate(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
    cert = x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(csr.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=90)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(ca_private_key, hashes.SHA256())
    return cert.public_bytes(Encoding.PEM).decode('utf-8')

def revoke_certificate(serial_number):
    crl.add(serial_number)

def is_certificate_revoked(serial_number):
    return serial_number in crl

# Callback pour la connexion MQTT
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("vehicle")

# Callback pour la réception des messages MQTT
def on_message(client, userdata, msg):
    message = json.loads(msg.payload)
    action = message.get("action")
    if action == "issue":
        csr = message.get("csr")
        if csr:
            cert = issue_certificate(csr)
            client.publish("vehicle", json.dumps({"certificate": cert}))
    elif action == "revoke":
        serial_number = message.get("serial_number")
        if serial_number:
            revoke_certificate(serial_number)
            client.publish("vehicle", json.dumps({"status": "revoked"}))
    elif action == "check_revocation":
        serial_number = message.get("serial_number")
        if serial_number:
            revoked = is_certificate_revoked(serial_number)
            client.publish("vehicle", json.dumps({"revoked": revoked}))

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("194.57.103.203", 1883, 60)
client.loop_forever()