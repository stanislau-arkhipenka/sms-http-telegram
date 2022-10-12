import sys
import base64
import logging
import json

from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        try:
            with open("./config.json") as f:
                self.srv_conf = json.load(f)
        except Exception as e:
            logger.warning("Unable to load login/password")
            self.srv_conf = {}

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
            print(message)
        except Exception as e:
            logger.error("Unable to process request", exc_info=e)


if __name__ == "__main__":

    with HTTPServer(("0.0.0.0", 8000), RequestHandler) as server:
        server.serve_forever()