import json  # Pour manipuler les données JSON
import paho.mqtt.client as mqtt  # Pour la communication via le protocole MQTT
from cryptography import x509  # Pour la gestion des certificats X.509
from cryptography.hazmat.primitives import hashes  # Pour les fonctions de hachage
import os  # Pour les opérations système, ici utilisé pour générer une clé de session aléatoire
import time  # Pour les opérations basées sur le temps, comme les pauses
from cryptography.hazmat.primitives.asymmetric import padding  # Pour les opérations de chiffrement asymétrique


# Fonction permettant le Chargement du certificat de l'autorité de certification (CA) par le client
def load_ca_certificate():
    with open("ca_certificate.pem", "rb") as f: 
        ca_cert = x509.load_pem_x509_certificate(f.read())  # Charge le certificat en format PEM
    return ca_cert  # Retourne le certificat de la CA

# Charge le certificat de la CA dès le debut dans le but de vérifier la validité et l'authenticité du certificat du vendeur lors d'un achat
ca_cert = load_ca_certificate()

# Vérification du certificat signé du vendeur par la CA
def verify_certificate(client_cert_pem):
    client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))  # Charge le certificat du vendeur en format PEM
    ca_public_key = ca_cert.public_key()  # Récupère la clé publique de la CA
    try:
        # Vérifie la signature du certificat du client en utilisant la clé publique de la CA
        ca_public_key.verify(
            client_cert.signature,  # La signature du certificat du vendeur à vérifier
            client_cert.tbs_certificate_bytes,  # Le contenu du certificat qui a été signé
            padding.PKCS1v15(),  # Utilise le schéma de padding PKCS#1 v1.5 pour la vérification
            client_cert.signature_hash_algorithm  # Utilise l'algorithme de hachage spécifié dans le certificat
        )
        print("Le certificat du Vendeur est valide et signé par la CA.")
        return client_cert  # Retourne le certificat si valide
    except Exception as e:
        print(f"Le certificat du Vendeur est invalide: {e}")
        return None  # Retourne None si la vérification échoue

# Fonction permettant l'Envoie de la clé de session chiffrée au vendeur
def send_session_key():
    # Génère aléatoirement une clé de session (32 octets pour AES-256)
    session_key = os.urandom(32) 

    # Charge le certificat du vendeur pour obtenir sa clé publique
    with open("vendeur_certificate.pem", "r") as f:
        certificate = f.read()
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    client_public_key = cert.public_key()  # Obtient la clé publique du certificat

    # Le client Chiffre la clé de session avec la clé publique du vendeur en utilisant OAEP
    encrypted_session_key = client_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 basé sur SHA-256
            algorithm=hashes.SHA256(),  # Algorithme de hachage SHA-256
            label=None
        )
    )

    # Envoie la clé de session chiffrée au Vendeur sous forme hexadécimale
    client.publish("vehicle/session_key", json.dumps({"encrypted_session_key": encrypted_session_key.hex()}))
    print("Clé de session chiffré est envoyé au vendeur. ")

# Fonction permettant au client de Vérifier si le certificat du vendeur est révoqué
def isRevoke():
    # Charge le certificat du vendeur pour obtenir son numéro de série
    with open("vendeur_certificate.pem", "r") as f:
        certificate = f.read()
    cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    serial_number = cert.serial_number  # Récupère le numéro de série du certificat
    
    # Envoie un message ou Publie une requête à la CA pour vérifier la révocation du certificat en envoyant le numéro de série
    client.publish("vehicle", json.dumps({"action": "check_revocation", "serial_number": serial_number}))

# Callback  ou fonction pour la connexion du client au Broker MQTT
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))  # Affiche le code de résultat de la connexion
    client.subscribe("vehicle")  # S'abonne au topic "vehicle" pour recevoir les messages provenant de ce topic 
    client.subscribe("vehicle/achat")  # S'abonne au topic "vehicle/achat"  
    client.publish("vehicle/achat", json.dumps({"action": "get_certificate"}))  # Demande le certificat du vendeur

# Callback pour la réception des messages MQTT par le client
def on_message(client, userdata, msg):
    message = json.loads(msg.payload)  # Analyse le message JSON reçu
    
    # Si le message provient du topic "vehicle/achat"
    if msg.topic == "vehicle/achat":  
        certificate = message.get("certificate")  # Récupère le certificat du message
        if certificate:
            verified_cert = verify_certificate(certificate)  # Vérifie le certificat
            
            # Si le certificat est valide, il envoie la clé de session au vendeur.
            if verified_cert:
                print("Le certificat est valide, l'achat peut se faire")
                send_session_key()  # Envoie la clé de session au vendeur si le certificat est valide
            else:
                print("Le certificat n'est pas valide")
        time.sleep(2)  # Attente de 2 secondes
        
        isRevoke()  # Vérifie la révocation du certificat
        
    # Si le message provient du topic "vehicle" (envoyé par la CA )
    elif msg.topic == "vehicle":  
        revoked = message.get("revoked")  # Récupère l'état de révocation du message
        if revoked is not None:
            if revoked:
                print("Le certificat est révoqué.")  # Affiche si le certificat est révoqué
            else:
                print("Le certificat n'est pas révoqué.")  # Affiche si le certificat n'est pas révoqué

# Initialisation du client MQTT
client = mqtt.Client()               # Crée une instance du client MQTT
client.on_connect = on_connect       # Assigne le callback pour la connexion
client.on_message = on_message       # Assigne le callback pour la réception des messages
client.connect("194.57.103.203", 1883, 60)  # Se connecte au broker(serveur) MQTT à l'adresse spécifiée
client.loop_forever()               # Lance une boucle infinie pour maintenir la connexion et traiter les messages
