import sys
import base64
import logging
import json
import requests

from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)

ADDR="192.168.0.10"
PORT=8000

"""
config file:
{
    "login": "foo",
    "password": "bar",
    "token": "baz",
    "chat_map": [
        1: "123123123",
        2: "234234234"
    ]
}
"""


class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        with open(sys.argv[1]) as f:
            self.srv_conf = json.load(f)

        super().__init__(*args, **kwargs)

    def is_auth(self):
        if "login" not in self.srv_conf and "password" not in self.srv_conf:
            return True
        try:
            base_token = self.headers.get("Authorization", "")
            login, password = base64.b64decode(base_token[6:]).decode().split(":")
            if login == self.srv_conf.get("login") and \
                password == self.srv_conf.get("password"):
                return True
        except Exception as e:
            logger.error("Unable to check creds. ", exc_info=e)    

        return False


    def do_GET(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html;")
        self.end_headers()

    def do_POST(self):
        content_type = self.headers.get("Content-Type")
        if not self.is_auth():
            self.send_response(HTTPStatus.UNAUTHORIZED)
        if content_type != "application/json":
            self.send_response(HTTPStatus.BAD_REQUEST)
        try:
            length = int(self.headers.get('content-length'))
            message = json.loads(self.rfile.read(length))
            logger.info("Message received: %s", str(message))
            self.send_tg_message(message)
        except Exception as e:
            logger.error("Unable to process request", exc_info=e)
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def send_tg_message(self, data):
        str_d = f"FROM: {data.get('x1')}\nMESSAGE: {data.get('x3')}"
        sim_id = data.get('x2')
        token = self.srv_conf.get("token")
        url = f"https://api.telegram.org/bot{token}/sendMessage"

        payload = {
            "chat_id": self.srv_conf.get("chat_map", {})[sim_id],
            "text": str_d
        }
        headers = {
            "accept": "application/json",
            "User-Agent": "Telegram Bot SDK",
            "content-type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)
        logger.info("Telegram response: %s -- %s", response.status_code, response.text)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s][%(name)s] %(message)s",
        handlers=[
        logging.StreamHandler()
        ]
    )
    with HTTPServer((ADDR, PORT), RequestHandler) as server:
        server.serve_forever()