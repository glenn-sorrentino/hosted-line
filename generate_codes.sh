#!/bin/bash

# Create a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Generate invite codes
generate_codes() {
    python3 << EOF
from app import app, db, InviteCode
import secrets
from datetime import datetime, timedelta

def create_invite_code():
    with app.app_context():
        db.create_all()
        code = secrets.token_urlsafe(16)
        expiration_date = datetime.utcnow() + timedelta(days=365)
        new_code = InviteCode(code=code, expiration_date=expiration_date)
        db.session.add(new_code)
        db.session.commit()
        return code

if __name__ == '__main__':
    number_of_codes = int(input("Enter the number of invite codes to generate: "))
    for _ in range(number_of_codes):
        print(create_invite_code())
EOF
}

generate_codes