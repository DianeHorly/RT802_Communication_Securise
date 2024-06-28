# Importation des bibliothèques nécessaires
import json
import paho.mqtt.client as mqtt   # Pour la communication MQTT
from cryptography import x509   # Pour la gestion des certificats X.509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateSigningRequestBuilder, NameOID  # Pour créer les CSR(certificat)
from cryptography.hazmat.primitives import hashes   # Pour les fonctions de hachage
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Fonction pour générer une paire de clés du vendeur
def generate_client_key_pair():
    # Génère une clé privée RSA de 2048 bits
    vendeur_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Extraction de la clé publique associée
    vendeur_public_key = vendeur_private_key.public_key()
    
    # Sauvegarde la clé privée dans un fichier au format PEM
    with open("vendeur_private_key.pem", "wb") as f:
        f.write(vendeur_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
   
    # Sauvegarde la clé publique dans un fichier au format PEM
    with open("vendeur_public_key.pem", "wb") as f:
        f.write(vendeur_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return vendeur_private_key, vendeur_public_key

# Génération de la paire de clés du vendeur
vendeur_private_key, vendeur_public_key = generate_client_key_pair()

# Fonction permettant au vendeur de demander la création d'un certificat signé (CSR) à la CA
def create_csr(client_private_key, common_name):
    # Définition des informations du vendeur pour la creation de son CSR (certificat)
    csr = CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Client Organization"), x509.NameAttribute(NameOID.COMMON_NAME, common_name)])).sign(client_private_key, hashes.SHA256())
    
    # Retourne la CSR encodée en PEM
    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

# Création du certificat CSR pour le vendeur
csr = create_csr(vendeur_private_key, u"vendeur.example.com")

# Callback ou fonction appelé par le vendeur lors de la connexion au serveur MQTT
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    
    # le Vendeur s'abonne au topic ou canal "vehicle"
    client.subscribe("vehicle")
    
    # Le Vendeur envoie la démande de creation d'un certificat CSR  à la CA sur le topic "vehicle"
    client.publish("vehicle", json.dumps({"action": "issue", "csr": csr}))
    
    # Le vendeur s'abonne à topic "vehicle/achat" pour la réception de messages d'un client lors de l'achat 
    client.subscribe("vehicle/achat")
    
    # Le vendeur s'abonne à topic "vehicle/session_key" pour la réception de messages d'un client lors de l'achat
    # pour l'échange de la clé de session (secret partagé) afin d'assurer la sécurité.
    client.subscribe("vehicle/session_key")

# Callback appelé lors de la réception d'un message MQTT 
def on_message(client, userdata, msg):
    # Décodage du message JSON
    message = json.loads(msg.payload)
    
    # Gestion des messages reçus par le vendeur sur le topic "vehicle"
    if msg.topic == "vehicle":
        certificate = message.get("certificate")
        if certificate:
            # Sauvegarde le certificat signé reçu par la CA dans un fichier
            with open("vendeur_certificate.pem", "w") as f:
                f.write(certificate)
            print("Certificat reçu et sauvegardé dans le fichier vendeur_certificate.pem")
    
    # Gestion des messages reçus sur le topic "vehicle/achat"
    elif msg.topic == "vehicle/achat":
        action = message.get("action")
        if action == "get_certificate":
            # Lecture du certificat 
            with open("vendeur_certificate.pem", "r") as f:
                certificate = f.read()
                           
            # Le Vendeur envoie son certificat à la demande d'un client    
            client.publish("vehicle/achat", json.dumps({"certificate": certificate}))
    
    # Gestion des messages reçus sur le topic "vehicle/session_key"
    elif msg.topic == "vehicle/session_key":
        encrypted_session_key = bytes.fromhex(message.get("encrypted_session_key"))
        
        # Le vendeur Déchiffre la clé de session avec sa clé privée
        session_key = vendeur_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Decrypted session key:", session_key.hex())


# Initialisation du client MQTT
client = mqtt.Client()
client.on_connect = on_connect  # Assignation du callback pour la connexion à la file mqtt
client.on_message = on_message   # Assignation du callback pour la réception des messages

# Connexion au broker MQTT(serveur)
client.connect("194.57.103.203", 1883, 60)

# Boucle infinie pour maintenir la connexion et traiter les messages
client.loop_forever()