from flask import Flask, jsonify

from routes.auth_routes import auth_bp


app = Flask(__name__)

app.register_blueprint(auth_bp)


@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "system": "Secure Drone Fleet Management",
        "service": "Authentication API",
        "status": "running"
    })


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )