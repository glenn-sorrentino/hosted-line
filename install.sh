#!/bin/bash

# Update packages and install whiptail
sudo apt update
sudo apt install whiptail -y

# Collect variables using whiptail
DB_NAME=$(whiptail --inputbox "Enter the database name" 8 39 "hushlinedb" --title "Database Setup" 3>&1 1>&2 2>&3)
DB_USER=$(whiptail --inputbox "Enter the database username" 8 39 "hushlineuser" --title "Database Setup" 3>&1 1>&2 2>&3)
DB_PASS=$(whiptail --passwordbox "Enter the database password" 8 39 --title "Database Setup" 3>&1 1>&2 2>&3)

# Install Python, pip, and Git
sudo apt install python3 python3-pip git nginx -y

# Clone the repository
cd /var/www/html
git clone https://github.com/glenn-sorrentino/hosted-line
mv hosted-line hushline-hosted
cd hushline-hosted

# Create a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Create .env file for Flask app
echo "DB_NAME=$DB_NAME" >> .env
echo "DB_USER=$DB_USER" >> .env
echo "DB_PASS=$DB_PASS" >> .env

# Install Flask, Gunicorn, and other Python libraries
pip install Flask pymysql python-dotenv gunicorn

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
Environment="PATH=$WORKING_DIR/venv/bin"
ExecStart=$WORKING_DIR/venv/bin/gunicorn --workers 3 --bind unix:hushline-hosted.sock -m 007 wsgi:app

[Install]
WantedBy=multi-user.target
EOF

# Start and enable the Flask app service
sudo systemctl daemon-reload
sudo systemctl start hushline-hosted
sudo systemctl enable hushline-hosted

# Configure Nginx to proxy requests to the Flask app
NGINX_CONF=/etc/nginx/sites-available/hushline-hosted
cat <<EOF | sudo tee $NGINX_CONF
server {
    listen 80;
    server_name your_server_domain_or_IP;

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

# Install MySQL and set up the database
sudo apt install mysql-server -y
sudo mysql_secure_installation

# Create Database and User
sudo mysql -e "CREATE DATABASE $DB_NAME;"
sudo mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
sudo mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

echo "Installation and configuration complete."
