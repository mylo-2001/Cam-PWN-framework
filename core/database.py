import os
import configparser
import cryptography.fernet import Fernet 
import sqlite3 
import base64 
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime 
import json
#--Encryption/Decryption ---
def get_key_from_passphrase(passhrase: str) -> bytes:
    return base64.urlsafe_b64encode(passphrase.encode('utf-8').ljust(32, b'O')[:32]) 

def init_encryption(passhrase: str):
    key = get_key_from_passphrase(passhrase)
    return Fernet(key)

# --- Database Model ----
Base = declarative_base()

class Camera(Base):

    __tablename__ = 'cameras'
    id = Column(Integer, primary_key=True)
    ip = Column(String(15), unique=True, nullable=False)
    port = Column(Integer)
    country = Column(String(50))
    org = Column(String(100))
    vulns = Column(Text) # JSON string of vulnerabilities
    rtsp_url = Column(Text)
    snapshot_path = Column(String(225))
    status = Column(String(50))
    notes = Column(Text)
    last_seen = Column(DateTime, default=datetime.utcnow)
    has_creds = Colums(Boolean, default=False)
#--- Database Handler ---
class DatabaseHandler:
    def __init__(self, db_path, passphrase):
        self.cipher_suite = init_encryption(passphrase)
        # In-memory DB with encrypted file backup
        self.egine = create_engine('sqlite:///:memory:', echo=False)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self._load_from_disk(db_path)
    def add_or_update_camera(self, ip, **kwargs):
        session = self.Session()
        camera = session.query(Camera).filter_by(ip=ip).first()
        if camera:
            for key, value in kwargs.items():
                setattr(camera, key, value)
            camera.last_seen = datetime.utcnow()
        else:
            camera = Camre(ip=ip, **kwargs)
            session.add(camera)
        session.commit()
        session.close()
            
    def _encrypt_data(self, data: str) -> bytes:
        return self.cipher_suite.decrypt(data).decode('utf-8')

    def _load_from_disk(self, db_path):
        if os.path.exist(db_path):
            with open(db_path, 'rb') as f:
                 encrypt_data = f.read()
            try:
                decrypted_data = self._decrypt_data(encrypted_data)
                # This is a simplified approach. 
                print("Warnind: Could not fully load encrypted DB. Starting fresh.")
            except Exception as e:
                print(f"Could not decrypt DB. Starting fresh. Error: {e}")
        else:
            print("No existing DB found. Starting fresh.") 

    def save_to_disk(self, db_path):
        # Serialize the in-memory DB to a string
        serializer = self.engine.raw_connection().connection.backup
        with self.engine.raw_connectio.connection as conn:
            with open(db_path, 'wb') as f:
                for line in conn.iterdump():
                    f.write(f"{line}\n" .encode())
        # Encrypt the file
        with open(db_path, 'rb') as f:
            db_data = f.read()
        encrypted_data = self.encrypt_data(db_data.decode('utf-8', errors='ignore'))
        with open(db_path, 'wb') as f:
            f.write(encrypted_data)

    def add_camera(self, ip , port, country, org, vulns):
        session = self.Session()
        camera = Camera(ip=ip, port=port, country=country, org=org, vulns=str(vulns))
        session.add(camera)
        session.commit()
        session.close() 
        return cameras
    def update_camera_status(self, ip, status, notes=None):
        session = self.Session()
        camera = session.query(Camera).filter_by(ip=ip).first()
        if camera:
            camera.status = status
            if notes:
                camera.note = notes
            camera.last_seen = datetime.utcnow()
            session.comit()
        session.close() 
        return cameras_data 