from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)


@app.before_first_request
def create_tables():
    db.create_all()
    if not Product.query.first():
        products = [
            Product(name="Telefon", price=300),
            Product(name="Noutbuk", price=800),
            Product(name="Quloqchin", price=50)
        ]
        db.session.add_all(products)
        db.session.commit()


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Ma'lumot to‘liq emas"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Foydalanuvchi mavjud"}), 409

    hashed_password = generate_password_hash(data['password'])

    user = User(
        username=data['username'],
        password=hashed_password
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Ro‘yxatdan muvaffaqiyatli o‘tildi"}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    user = User.query.filter_by(username=data.get('username')).first()

    if not user or not check_password_hash(user.password, data.get('password')):
        return jsonify({"message": "Login yoki parol xato"}), 401

    token = create_access_token(identity=user.id)

    return jsonify({"access_token": token})


@app.route('/api/products', methods=['GET'])
@jwt_required()
def get_products():
    user_id = get_jwt_identity()

    products = Product.query.all()
    result = [
        {
            "id": p.id,
            "name": p.name,
            "price": p.price
        }
        for p in products
    ]

    return jsonify({
        "user_id": user_id,
        "products": result
    })


if __name__ == '__main__':
    app.run(debug=True)
