#!/usr/bin/env python3

from flask import Flask

app = Flask(__name__)
app.debug = True

@app.route("/validate")
def validate():
    return '{"access": true}'

if __name__ == "__main__":
    app.run()
