import json  # Pour manipuler les données JSON
import paho.mqtt.client as mqtt  # Pour la communication via le protocole MQTT
from cryptography import x509  # Pour la gestion des certificats X.509
from cryptography.hazmat.primitives import hashes  # Pour les fonctions de hachage
from cryptography.hazmat.primitives.asymmetric import padding  # Pour les opérations de chiffrement asymétrique avec padding
import os  # Pour les opérations système, ici utilisé pour générer une clé de session aléatoire

# Chargement du certificat de l'autorité de certification (CA) par le client
def load_ca_certificate():
    with open("ca_certificate.pem", "rb") as f:  
        ca_cert = x509.load_pem_x509_certificate(f.read())  # Charge le certificat en format PEM
    return ca_cert  # Retourne le certificat de la CA

# Charge le certificat de la CA dès le début dans le but de vérifier la validité et l'authenticité du certificat du vendeur lors d'un achat
ca_cert = load_ca_certificate()

# Vérification du certificat signé du vendeur par la CA
def verify_certificate(client_cert_pem):
    client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))  # Charge le certificat du client en format PEM
    ca_public_key = ca_cert.public_key()  # Récupère la clé publique de la CA
    try:
        # Vérifie la signature du certificat du vendeur en utilisant la clé publique de la CA
        ca_public_key.verify(
            client_cert.signature,  # La signature du certificat à vérifier
            client_cert.tbs_certificate_bytes,  # Le contenu du certificat qui a été signé
            padding.PKCS1v15(),  # Utilise le schéma de padding PKCS#1 v1.5 pour la vérification
            client_cert.signature_hash_algorithm  # Utilise l'algorithme de hachage spécifié dans le certificat
        )
        print("Le certificat du vendeur est valide et signé par la CA.")
        return client_cert  # Retourne le certificat si valide
    except Exception as e:
        print(f"Le certificat du Vendeur est invalide: {e}")
        return None  # Retourne None si la vérification échoue

# Envoie une clé de session chiffrée au vendeur
def send_session_key():
    # Génère une clé de session aléatoirement (32 octets pour AES-256)
    session_key = os.urandom(32)

    # Charge le certificat du vendeur pour obtenir sa clé publique
    with open("vendeur_certificate.pem", "r") as f:  # Ouvre le fichier contenant le certificat du vendeur en mode lecture
        certificate = f.read()
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))  # Charge le certificat en format PEM
    client_public_key = cert.public_key()  # Obtient la clé publique du certificat

    # Chiffre la clé de session avec la clé publique du Vendeur en utilisant OAEP
    encrypted_session_key = client_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 basé sur SHA-256
            algorithm=hashes.SHA256(),  # Algorithme de hachage SHA-256
            label=None
        )
    )

    # Envoie la clé de session chiffrée au vendeur sous forme hexadécimale
    client.publish("vehicle/session_key", json.dumps({"encrypted_session_key": encrypted_session_key.hex()}))
    print("Clé de session chiffré est envoyé au vendeur. ")

# Callback pour la connexion du client1 au serveur(broker) MQTT
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))  # Affiche le code de résultat de la connexion
    client.subscribe("vehicle")                   # S'abonne au topic "vehicle" pour recevoir les messages y provenant
    client.subscribe("vehicle/achat")             # S'abonne au topic "vehicle/achat" pour recevoir les messages y provenant
    
    # Envoie la demande du certificat du vendeur(au vendeur) pour vérifier son authenticité
    client.publish("vehicle/achat", json.dumps({"action": "get_certificate"}))

# Callback pour la réception des messages MQTT par le client
def on_message(client, userdata, msg):
    message = json.loads(msg.payload)  # Analyse le message JSON reçu
    
    # Si le message provient du topic "vehicle/achat"
    if msg.topic == "vehicle/achat":  
        certificate = message.get("certificate")  # Récupère le certificat du message
        if certificate:
            verified_cert = verify_certificate(certificate)  # Vérifie le certificat
            
            # Si le certificat est valide
            if verified_cert:
                print("Le certificat est valide, l'achat peut se faire")
                send_session_key()  # Envoie la clé de session au vendeur si le certificat est valide
            else:
                print("Le certificat n'est pas valide") # Sinon affiche un message de non validité 

# Initialisation du client MQTT
client = mqtt.Client()  # Crée une instance du client MQTT
client.on_connect = on_connect  # Assigne le callback pour la connexion
client.on_message = on_message  # Assigne le callback pour la réception des messages
client.connect("194.57.103.203", 1883, 60)  # Se connecte au broker MQTT à l'adresse spécifiée
client.loop_forever()  # Lance une boucle infinie pour maintenir la connexion et traiter les messages
