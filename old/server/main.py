# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import time
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler


class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        print("[{}] Request arrived from {}".format(datetime.now(), self.client_address))


# Press the green button in the gutter to arun the script.
if __name__ == '__main__':
    port = 80
    server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(server_address, MyHandler)
    print("Serving on port {}".format(port))
    httpd.serve_forever()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
