from mwdb.model import User
from mwdb.cli.base import create_app

app = create_app()
with app.app_context():
    user = User.get_by_login('admin')
    if user and user.api_keys:
        print(user.api_keys[0].key)
    else:
        print("No admin API key found")
