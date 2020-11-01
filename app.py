import datetime
import os
import json
from json import dumps
from functools import wraps

from bson import json_util, ObjectId
from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import jwt

from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_restful.representations import json
from flask_cors import CORS, cross_origin
from bson import ObjectId

from model import JSONEncoder
import flask_excel as excel

app = Flask(__name__)
excel.init_excel(app)
app.config['SECRET_KEY'] = 'jai shivrai jai jijau jai sambhaji'
app.config['MONGO_DBNAME'] = 'tmm'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/tmm'
mongo = PyMongo(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

# Bcrypt algorithm hashing rounds
BCRYPT_LOG_ROUNDS = 15


# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Missing JSON in request', 'access_token': ''}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({'success': False, 'message': 'Missing username parameter', 'access_token': ''}), 400
    if not password:
        return jsonify({'success': False, 'message': 'Missing password parameter', 'access_token': ''}), 400

    # if username != 'test' or password != 'test':
    #     return jsonify({"msg": "Bad username or password"}), 401

    result_obj = mongo.db.tmm_users.find_one({'username': username})
    if result_obj:
        res = bcrypt.check_password_hash(result_obj['password'], password)
        if res and result_obj['password']:
            # Token will expire in 5 minutes
            access_token = jwt.encode(
                {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)},
                app.config['SECRET_KEY'], algorithm='HS256').decode(
                'utf-8')
            return jsonify({'success': True, 'message': '', 'access_token': access_token}), 200
        else:
            return jsonify({'success': False, 'message': 'username or password are not valid', 'access_token': ''}), 401
    else:
        return jsonify({'success': False, 'message': 'username or password are not valid', 'access_token': ''}), 401


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('access_token')

        if not token:
            return jsonify(
                {'success': False, 'message': 'Token in missing, Please login again!', 'access_token': ''}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify(
                {'success': False, 'message': 'Token in invalid, Please login again!', 'access_token': ''}), 403

        return f(*args, **kwargs)

    return decorated


@app.route('/addUser', methods=['POST'])
@token_required
def add_user():
    name = request.json.get('name', None)
    is_father = request.json.get('is_father', None)
    father_husband = request.json.get('father_husband', None)
    aadhar_no = request.json.get('aadhar_no', None)
    date_of_birth = request.json.get('date_of_birth', None)
    address = request.json.get('address', None)
    pincode = request.json.get('pincode', None)
    mobile = request.json.get('mobile', None)
    house = request.json.get('house', None)
    occupation = request.json.get('occupation', None)
    email = request.json.get('email', None)
    qualification = request.json.get('qualification', None)
    district = request.json.get('district', None)
    members = request.json.get('other', None)

    json_data = {'name': name,
                 'is_father': is_father,
                 'father_husband': father_husband,
                 'aadhar_no': aadhar_no,
                 'date_of_birth': date_of_birth,
                 'address': address,
                 'pincode': pincode,
                 'mobile': mobile,
                 'house': house,
                 'occupation': occupation,
                 'email': email,
                 'qualification': qualification,
                 'district': district,
                 'members': members
                 }

    if name and request.method == 'POST':
        result = mongo.db.users.insert_one(json_data)
        return jsonify(
            {'success': True, 'message': 'User added successfully!', 'user_id': str(result.inserted_id)}), 200
    else:
        return not_found()


@app.errorhandler(404)
def not_found(error=None):
    return jsonify({'success': True, 'message': 'This URL not found ' + request.url}), 404


@app.route('/')
@token_required
def index():
    # result = mongo.db.users.insert_one({'name': 'test', 'email': 'test@test.com'})
    return 'This is index page'


@app.route('/add_admin')
def admin():
    admin_password = bcrypt.generate_password_hash('admin')
    result = mongo.db.tmm_users.insert_one({'username': 'admin', 'password': admin_password})
    return 'Admin created Successfully.'


@app.route('/generate')
def generate():
    admin_password = bcrypt.generate_password_hash('admin')
    res = bcrypt.check_password_hash(admin_password, 'admin')
    print(res)
    return admin_password


@app.route('/get_users')
@cross_origin()
@token_required
def get_users():
    result = mongo.db.users
    output = []

    for user in result.find():
        output.append({'id': str(user['_id']), 'name': user['name'], 'email': user['email'],
                       'father_husband': user['father_husband'], 'date_of_birth': user['date_of_birth'],
                       'address': user['address'], 'mobile': user['mobile'],
                       'qualification': user['qualification'], 'members': user['members']})

    if len(output) > 0:
        return jsonify({'success': True, 'message': '', 'data': output}), 200
    else:
        return jsonify({'success': False, 'message': 'No records', 'data': ''}), 200


@app.route("/upload", methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        return jsonify({"result": request.get_array(field_name='file')})
    return '''
    <!doctype html>
    <title>Upload an excel file</title>
    <h1>Excel file upload (csv, tsv, csvz, tsvz only)</h1>
    <form action="" method=post enctype=multipart/form-data><p>
    <input type=file name=file><input type=submit value=Upload>
    </form>
    '''


@app.route("/download", methods=['GET'])
def download_file():
    return excel.make_response_from_array([[1, 2], [3, 4]], "csv")


@app.route("/export", methods=['GET'])
def export_records():
    return excel.make_response_from_array([[1, 2], [3, 4]], "csv",
                                          file_name="export_data")


if __name__ == '__main__':
    app.run(debug=True)
