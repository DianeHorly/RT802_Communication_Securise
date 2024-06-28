# importation des Bibliothèque necessaires

import json  # Pour manipuler les données JSON
import paho.mqtt.client as mqtt  # Pour la communication via le protocole MQTT
from cryptography import x509  # Pour la gestion des certificats X.509
from cryptography.hazmat.primitives import hashes  # Pour les fonctions de hachage
import time  # Pour les opérations basées sur le temps (comme les pauses)
import os  # Pour les opérations système, ici utilisé pour générer une clé de session aléatoire
from cryptography.hazmat.primitives.asymmetric import padding  # Pour les opérations de chiffrement asymétrique

# Le client Charge le certificat de l'autorité de certification (CA) à partir d'un fichier PEM.
# afin de vérifier la validité et l'authenticité du certificat du vendeur lors d'un achat
def load_ca_certificate():
    with open("ca_certificate.pem", "rb") as f: #Ouvre le fichier ca_certificate.pem en mode binaire (rb) et le lit
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_cert

ca_cert = load_ca_certificate()

# Fonction pour Vérifier si le certificat du vendeur est valide et signé par la CA de confiance.
def verify_certificate(client_cert_pem):
    # charge la certificat du vendeur en format PEM
    client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))
    # Récupère la clé publique de la CA.
    ca_public_key = ca_cert.public_key()
    
    # Le client Utilise cette clé pour vérifier l'authenticité de la signature du certificat du Vendeur.
    try:
        # Si la signature est valide, affiche un message de confirmé confirmation
        ca_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm
        )
        print("Le certificat du Vendeur est valide et signé par la CA.")
        return client_cert
    # Dans le cas contraire, affiche une message d'invalidité
    except Exception as e:
        print(f"Le certificat du Vendeur est invalide: {e}")
        return None
    
# Fonction pour sécuriser les communications en transmettant une clé de session chiffrée.    
def send_session_key():
    # Génère une clé de session aléatoirement (32 octets pour AES-256).
    session_key = os.urandom(32)  # AES-256 

    # charge le certificat du vendeur pour obtenir la clé publique.
    with open("vendeur2_certificate.pem", "r") as f:
        certificate = f.read()
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    client_public_key = cert.public_key()

    # Le client utilise cette clé publique(vendeur) pour chiffrer la clé de session en utilisant OAEP.
    encrypted_session_key = client_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Le client Envoie la clé de session chiffrée sous forme hexadécimale sur le topic MQTT vehicle/session_key
    client.publish("vehicle/session_key", json.dumps({"encrypted_session_key": encrypted_session_key.hex()}))
    print("Clé de session chiffré est envoyé au vendeur. ")

#  Fonction pour déterminer si le certificat du vendeur est toujours valide ou s'il a été révoqué.
def isRevoke():
    with open("vendeur2_certificate.pem", "r") as f:
        certificate = f.read()
    # Charge le certificat du vendeur pour obtenir son numéro de série.    
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    serial_number = cert.serial_number
    
    # Le client Envoie ou publie une requête sur le topic MQTT vehicle pour vérifier la révocation du certificat en envoyant le numéro de série.
    client.publish("vehicle", json.dumps({"action": "check_revocation", "serial_number": serial_number}))

# Callback ou fonction pour Gérer la connexion du client au broker MQTT
def on_connect(client, userdata, flags, rc):
    # Affiche le code de résultat de la connexion.
    print("Connected with result code "+str(rc))
    # Le client s'abonne ou se connecte aux topics "vehicle" et "vehicle/achat"
    client.subscribe("vehicle")
    client.subscribe("vehicle/achat")
    
    # Le client envoie une requête au vendeur pour obtenir son certificat signé via le topic vehicle/achat.
    client.publish("vehicle/achat", json.dumps({"action": "get_certificate"}))

# Callback pour gérer la réception des messages MQTT par le chient
def on_message(client, userdata, msg):
    # Analyse le message JSON reçu.
    message = json.loads(msg.payload)   # Analyse le message JSON reçu
    
    # Si le message provient du topic vehicle/achat, il tente de vérifier le certificat reçu du Vendeur.
    if msg.topic == "vehicle/achat":
        certificate = message.get("certificate") # Récupère le certificat du message
        if certificate:
            verified_cert = verify_certificate(certificate)
            
            # Si le certificat est valide, il envoie la clé de session au vendeur.
            if verified_cert:
                print("Le certificat est valide, l'achat peut se faire")
                send_session_key()   # Envoie la clé de session si le certificat est valide
            else:
                print("Le certificat n'est pas valide")
                
        time.sleep(2)   # Attente de 2 secondes
        
        # Vérifie la révocation du certificat après une pause.
        isRevoke()
        
    # Si le message provient du topic vehicle (envoyé par la CA), il vérifie l'état de révocation et affiche un message en conséquence.    
    elif msg.topic == "vehicle":
        revoked = message.get("revoked")     # Récupère l'état de révocation du message
        if revoked is not None:
            if revoked:
                print("Le certificat est révoqué.")
            else:
                print("Le certificat n'est pas révoqué.")

# Initialisation du client MQTT
client = mqtt.Client()
client.on_connect = on_connect  # Assignation du callback pour la connexion à la file mqtt
client.on_message = on_message   # Assignation du callback pour la réception des messages

# Connexion au broker MQTT(serveur)
client.connect("194.57.103.203", 1883, 60)

# Boucle infinie pour maintenir la connexion et traiter les messages
client.loop_forever()