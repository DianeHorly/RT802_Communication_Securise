# Importation des bibliothèque nécessaires pour implementer la ca
import json
import paho.mqtt.client as mqtt  # Pour la communication MQTT
from cryptography import x509  # Pour la gestion des certificats X.509
from cryptography.hazmat.primitives import hashes  # Pour les fonctions de hachage
from cryptography.hazmat.primitives.asymmetric import rsa  # Pour les opérations RSA
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption  # Pour la sérialisation des clés
from cryptography.x509.oid import NameOID  # Pour les identifiants des attributs dans les certificats
from datetime import datetime, timedelta  # Pour gérer les dates et les durées


# Fonction pour générer un certificat  par l'autorité (CA)
def generate_ca_certificate():
    # Génération de la clé privée RSA
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Définition des attributs (informations de la CA) pour l'émission du certificat
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Ma CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ca.example.com"),
    ])
    
    # Construction du certificat de la CA
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key, hashes.SHA256())
    
    # Sauvegarde de la clé privée et du certificat sur le disque
    with open("ca_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption()))
    with open("ca_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    return private_key, cert

# Génération du certificat de la CA
ca_private_key, ca_cert = generate_ca_certificate()

# Liste  pour mettre les certificats révoqués
crl = set()

# Fonction pour émettre un certificat par la CA lors d'une demande de signature de certificat (CSR) par un vedeur ou un client
def issue_certificate(csr_pem):
    
    # Chargement de la CSR au format PEM
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
    
    # Construction du certificat   
    cert = x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(csr.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=90)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(ca_private_key, hashes.SHA256())
    
    # Retourne le certificat au format PEM
    return cert.public_bytes(Encoding.PEM).decode('utf-8')

# Fonction pour révoquer un certificat en ajoutant son numéro de série à la liste des révocations
def revoke_certificate(serial_number):
    crl.add(serial_number)

# Fonction pour vérifier si un certificat est révoqué
def is_certificate_revoked(serial_number):
    return serial_number in crl

# Fonction appelée lors de la connexion MQTT(pour permettre à la CA se connecter sur la file MQTT)
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    # Connexion de la CA sur le topic(canal) vehicle
    client.subscribe("vehicle")

# Fonction appelé par la CA lors de la réception d'un message dans la file MQTT
def on_message(client, userdata, msg):
    message = json.loads(msg.payload) # Décodage du message JSON
    action = message.get("action")    # Extraction de l'action à effectuer
    
    # Émission d'un certificat si l'action est 'issue'
    # Dans ce cas la CA appelle la fonction issue_certificate(csr_pem)
    if action == "issue":
        csr = message.get("csr")
        if csr:
            cert = issue_certificate(csr)
            
            # La CA Renvoie le certificat à l'émmetteur de la demande du certificat par le canal vehicle
            client.publish("vehicle", json.dumps({"certificate": cert}))
    
    # Révocation d'un certificat par la CA si l'action est 'revoke'
    elif action == "revoke":
        serial_number = message.get("serial_number")
        if serial_number:
            revoke_certificate(serial_number)
            
            # La CA Renvoie le status du certificat à l'émmetteur de la demande par le canal vehicle
            client.publish("vehicle", json.dumps({"status": "revoked"}))
    
    # Vérification de la révocation d'un certificat si l'action est 'check_revocation'
    # Dans ce cas la CA appelle la fonction  is_certificate_revoked(serial_number)
    elif action == "check_revocation":
        serial_number = message.get("serial_number")
        if serial_number:
            revoked = is_certificate_revoked(serial_number)
        
            # La CA Renvoie le message "revoked" à l'émmetteur de la demande de verification du certificat par le canal vehicle   
            client.publish("vehicle", json.dumps({"revoked": revoked}))

# Initialisation du client MQTT
client = mqtt.Client()
client.on_connect = on_connect  # Assignation du callback pour la connexion à la file mqtt
client.on_message = on_message   # Assignation du callback pour la réception des messages

# Connexion au broker MQTT(serveur)
client.connect("194.57.103.203", 1883, 60)

# Boucle infinie pour maintenir la connexion et traiter les messages
client.loop_forever()