import sys
sys.path.append('/app')
import logging
import datetime
from flask import g

from mwdb.cli.base import create_app
from mwdb.model import db, User, APIKey
import uuid
from sqlalchemy.exc import IntegrityError

def bootstrap():
    print("Bootstrapping MWDB...")
    app = create_app()
    with app.app_context():
        # Ensure tables
        db.create_all()
        
        # Check existing
        u = User.query.filter(User.login == 'admin').first()
        
        if not u:
            print("Creating admin user via User.create...")
            # Mock g.auth_user for User.create
            g.auth_user = None
            
            try:
                # additional_info passed as string "{}" just in case, or empty dict if it serializes. 
                # Model definition saw db.String but usually it's JSON.
                # Let's try passing empty dict, if it fails, we know. 
                # Actually, given the error, let's pass a JSON string to be safe if it is a string column.
                # But wait, looking at my `cat` output again...
                # It was `additional_info = db.Column(db.String, nullable=False)`
                # I will pass "{}"
                
                u = User.create(
                    login='admin',
                    email='admin@localhost',
                    additional_info="{}", 
                    commit=False
                )
                
                u.set_password('admin')
                db.session.commit()
                print("User created successfully.")
                
            except Exception as e:
                print(f"User creation failed: {e}")
                import traceback
                traceback.print_exc()
                db.session.rollback()
                u = User.query.filter(User.login == 'admin').first()
        
        if not u:
            print("Failed to get or create user.")
            return

        print(f"User ID: {u.id}")
        
        # Check if key exists
        key = APIKey.query.filter(APIKey.user_id == u.id, APIKey.name == 'initial-admin-key').first()
        if not key:
            print("Creating API key...")
            new_id = uuid.uuid4()
            key = APIKey(id=new_id, user_id=u.id, name='initial-admin-key', issued_by=u.id)
            db.session.add(key)
            db.session.commit()
            print("API key created.")
        else:
            print("API key already exists.")

        if key:
            print(f"Admin API Key: {key.generate_token()}")

if __name__ == "__main__":
    bootstrap()
