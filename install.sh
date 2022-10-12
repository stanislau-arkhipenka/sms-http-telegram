#!/bin/bash

sudo cp -r $(pwd) /opt/sms_http_telegram
virtualenv -p python3 /opt/sms_http_telegram/.venv
source /opt/sms_http_telegram/.venv/bin/activate
pip3 install -r requirements.txt
sed "s/MY_USER/$USER/g" example.service > sms_http_telegram.service
sudo mv ./sms_http_telegram.service.service /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl enable hexapod.service