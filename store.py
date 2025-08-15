import os
import hashlib
from flask import Flask, request, send_file, abort, Response
from functools import wraps
from pathlib import Path

app = Flask(__name__)

USERS = {"admin": "secret", "test": "123"}
STORE_DIR = Path("store")
FILE_OWNERS = {}

def check_credentials(username, password):
    return USERS.get(username) == password

def need_auth():
    return Response("Авторизуйся!", 401, {"WWW-Authenticate": 'Basic realm="Login"'})

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_credentials(auth.username, auth.password):
            return need_auth()
        return f(auth.username, *args, **kwargs)
    return wrapper

def get_filepath(file_hash):
    return STORE_DIR / file_hash[:2] / file_hash

def hash_file(file):
    sha256 = hashlib.sha256()
    file.seek(0)
    while chunk := file.read(4096):
        sha256.update(chunk)
    return sha256.hexdigest()

@app.route('/')
def index():
    return """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Хранилище</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h2>Хранилище файлов</h2>
        <div class="mt-3">
            <h5>Загрузка</h5>
            <input type="text" class="form-control mb-2" id="username" placeholder="Логин">
            <input type="password" class="form-control mb-2" id="password" placeholder="Пароль">
            <input type="file" class="form-control mb-2" id="fileInput">
            <button class="btn btn-primary" onclick="upload()">Загрузить</button>
            <div id="uploadResult" class="mt-2"></div>
        </div>
        <div class="mt-3">
            <h5>Скачивание</h5>
            <input type="text" class="form-control mb-2" id="downloadHash" placeholder="Хэш файла">
            <button class="btn btn-success" onclick="download()">Скачать</button>
        </div>
        <div class="mt-3">
            <h5>Удаление</h5>
            <input type="text" class="form-control mb-2" id="deleteUsername" placeholder="Логин">
            <input type="password" class="form-control mb-2" id="deletePassword" placeholder="Пароль">
            <input type="text" class="form-control mb-2" id="deleteHash" placeholder="Хэш файла">
            <button class="btn btn-danger" onclick="deleteFile()">Удалить</button>
            <div id="deleteResult" class="mt-2"></div>
        </div>
    </div>
    <script>
        function upload() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const file = document.getElementById('fileInput').files[0];
            const result = document.getElementById('uploadResult');
            if (!file || !username || !password) {
                result.innerHTML = '<div class="alert alert-danger">Заполни все!</div>';
                return;
            }
            const formData = new FormData();
            formData.append('file', file);
            fetch('/upload', {
                method: 'POST',
                headers: { 'Authorization': 'Basic ' + btoa(username + ':' + password) },
                body: formData
            })
            .then(res => res.json().then(data => ({status: res.status, body: data})))
            .then(data => {
                result.innerHTML = data.status === 201 
                    ? `<div class="alert alert-success">Готово! Хэш: ${data.body.hash}</div>`
                    : `<div class="alert alert-danger">Ошибка: ${data.body.description}</div>`;
            })
            .catch(() => result.innerHTML = '<div class="alert alert-danger">Проблема!</div>');
        }
        function download() {
            const fileHash = document.getElementById('downloadHash').value;
            if (!fileHash) return alert('Введи хэш!');
            window.location.href = `/download/${fileHash}`;
        }
        function deleteFile() {
            const username = document.getElementById('deleteUsername').value;
            const password = document.getElementById('deletePassword').value;
            const fileHash = document.getElementById('deleteHash').value;
            const result = document.getElementById('deleteResult');
            if (!fileHash || !username || !password) {
                result.innerHTML = '<div class="alert alert-danger">Заполни все!</div>';
                return;
            }
            fetch(`/delete/${fileHash}`, {
                method: 'DELETE',
                headers: { 'Authorization': 'Basic ' + btoa(username + ':' + password) }
            })
            .then(res => res.json().then(data => ({status: res.status, body: data})))
            .then(data => {
                result.innerHTML = data.status === 200 
                    ? '<div class="alert alert-success">Удалено!</div>'
                    : `<div class="alert alert-danger">Ошибка: ${data.body.description}</div>`;
            })
            .catch(() => result.innerHTML = '<div class="alert alert-danger">Проблема!</div>');
        }
    </script>
</body>
</html>
"""

@app.route('/upload', methods=['POST'])
@auth_required
def upload(username):
    if 'file' not in request.files or not request.files['file'].filename:
        abort(400, description="Нет файла!")
    
    file = request.files['file']
    file_hash = hash_file(file)
    file_path = get_filepath(file_hash)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    file.seek(0)
    file.save(file_path)
    FILE_OWNERS[file_hash] = username
    
    return {"hash": file_hash}, 201

@app.route('/download/<file_hash>')
def download(file_hash):
    file_path = get_filepath(file_hash)
    if not file_path.exists():
        abort(404, description="Файл не найден!")
    return send_file(file_path, as_attachment=True)

@app.route('/delete/<file_hash>', methods=['DELETE'])
@auth_required
def delete(username, file_hash):
    file_path = get_filepath(file_hash)
    if not file_path.exists():
        abort(404, description="Файл не найден!")
    if file_hash not in FILE_OWNERS or FILE_OWNERS[file_hash] != username:
        abort(403, description="Это не твой файл!")
    
    file_path.unlink()
    del FILE_OWNERS[file_hash]
    return {"message": "Удалено"}, 200

if __name__ == '__main__':
    STORE_DIR.mkdir(exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)