#!/bin/bash

# Update packages and install whiptail
sudo apt update
sudo apt install whiptail -y

# Collect variables using whiptail
DB_NAME=$(whiptail --inputbox "Enter the database name" 8 39 "hushlinedb" --title "Database Setup" 3>&1 1>&2 2>&3)
DB_USER=$(whiptail --inputbox "Enter the database username" 8 39 "hushlineuser" --title "Database Setup" 3>&1 1>&2 2>&3)
DB_PASS=$(whiptail --passwordbox "Enter the database password" 8 39 "dbpassword" --title "Database Setup" 3>&1 1>&2 2>&3)

# Install Python, pip, Git, Nginx, and MariaDB
sudo apt install python3 python3-pip git nginx default-mysql-server python3-venv gnupg -y

# Clone the repository
cd /var/www/html
git clone https://github.com/glenn-sorrentino/hosted-line
mv hosted-line hushline-hosted
cd hushline-hosted

mkdir ~/.gnupg
chmod 700 ~/.gnupg

# Create a Python virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install Flask, Gunicorn, and other Python libraries
pip install Flask pymysql python-dotenv gunicorn Flask-SQLAlchemy Flask-Bcrypt pyotp qrcode python-gnupg

SECRET_KEY=$(python3 -c 'import os; print(os.urandom(64).hex())')

# Create .env file for Flask app
echo "DB_NAME=$DB_NAME" > .env
echo "DB_USER=$DB_USER" >> .env
echo "DB_PASS=$DB_PASS" >> .env
echo "SECRET_KEY=$SECRET_KEY" >> .env

# Start MariaDB
sudo systemctl start mariadb

# Secure MariaDB Installation
sudo mysql_secure_installation

# Check if the database exists, create if not
if ! sudo mysql -sse "SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = '$DB_NAME')" | grep -q 1; then
    sudo mysql -e "CREATE DATABASE $DB_NAME;"
fi

# Check if the user exists and create it if it doesn't
if ! sudo mysql -sse "SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = '$DB_USER' AND host = 'localhost')" | grep -q 1; then
    sudo mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    sudo mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    sudo mysql -e "FLUSH PRIVILEGES;"
fi

# Verify Database Connection and Initialize DB
echo "Verifying database connection and initializing database..."
if ! python init_db.py; then
    echo "Database initialization failed. Please check your settings."
    exit 1
else
    echo "Database initialized successfully."
fi

# Define the working directory
WORKING_DIR=$(pwd)

# Create a systemd service file for the Flask app
SERVICE_FILE=/etc/systemd/system/hushline-hosted.service
cat <<EOF | sudo tee $SERVICE_FILE
[Unit]
Description=Gunicorn instance to serve the Hushline Flask app
After=network.target

[Service]
User=$USER
Group=www-data
WorkingDirectory=$WORKING_DIR
ExecStart=$WORKING_DIR/venv/bin/gunicorn --workers 2 --bind unix:$WORKING_DIR/hushline-hosted.sock -m 007 --timeout 120 wsgi:app

[Install]
WantedBy=multi-user.target
EOF

# Start and enable the Flask app service
sudo systemctl daemon-reload
sudo systemctl start hushline-hosted
sudo systemctl enable hushline-hosted
sudo systemctl restart hushline-hosted

# Configure Nginx to proxy requests to the Flask app
NGINX_CONF=/etc/nginx/sites-available/hushline-hosted
cat <<EOF | sudo tee $NGINX_CONF
server {
    listen 80;
    server_name localhost 164.92.99.92;

    location / {
        include proxy_params;
        proxy_pass http://unix:$WORKING_DIR/hushline-hosted.sock;
    }
}
EOF

# Enable the Nginx configuration
sudo ln -sf $NGINX_CONF /etc/nginx/sites-enabled/

# Restart Nginx to apply changes
sudo systemctl restart nginx

# Start and enable Nginx
sudo systemctl enable nginx

echo "Installation and configuration complete."