from flask import *
import requests
import re
from pymongo import MongoClient
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os.path
import base64
from email.mime.text import MIMEText
import googleapiclient.discovery
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.recaptcha import RecaptchaField
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/",
)
app.secret_key = "22303248"  # session有密鑰，自己設定
# 限制請求速率防止大量提交表單
limiter = Limiter(
    get_remote_address, app=app, default_limits=["200 per day", "50 per hour"]
)

# 配置 reCAPTCHA
app.config["RECAPTCHA_PUBLIC_KEY"] = "6LfLPnwqAAAAALG7AW42sl3IWvS3NnxRrTcoDygK"
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LfLPnwqAAAAALG7AW42sl3IWvS3NnxRrTcoDygK"
csrf = CSRFProtect(app)


class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    honeypot = StringField("Leave this empty", validators=[Length(max=0)])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    honeypot = StringField("Leave this empty", validators=[Length(max=0)])
    submit = SubmitField("Login")


def verify_recaptcha(response):
    secret = app.config["RECAPTCHA_PRIVATE_KEY"]
    payload = {"secret": secret, "response": response}
    r = requests.post("https://www.google.com/recaptcha/enterprise.js", data=payload)
    result = r.json()
    return result.get("success", False)


# 連接MongoDB
client = MongoClient(
    "mongodb+srv://william10310406:A22303248@cluster0.mpwsv.mongodb.net/"
)
db = client["flask"]  # 選擇資料庫
collection = db["user"]  # 選擇集合

# 如果修改這些範圍，刪除 token.json 文件
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


def get_credentials():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


# 寄送郵件的function
def send_email(to, subject, body):
    creds = get_credentials()
    service = googleapiclient.discovery.build("gmail", "v1", credentials=creds)
    message = MIMEText(body)
    message["to"] = to
    message["subject"] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message = {"raw": raw}
    service.users().messages().send(userId="me", body=message).execute()


# 首頁
@app.route("/")
def index():
    return render_template("index.html")


# 防爬蟲
@app.before_request
def block_user_agents():
    user_agent = request.headers.get("User-Agent")
    if "bot" in user_agent.lower() or "spider" in user_agent.lower():
        return "Access denied", 403


# 註冊頁面
@app.route("/registerpage", methods=["GET", "POST"])
def registerpage():
    return render_template("register.html")


# 註冊功能
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        # 驗證格式
        # 1.兩個都不能為空
        if not email or not password:
            flash("帳號密碼不能為空")
            return redirect(url_for("register"))
        # 2.gmail格式
        if not re.match(r"^[a-zA-Z0-9_.+-]+@gmail\.com$", email):
            flash("請使用 Gmail 地址註冊")
            return redirect(url_for("register"))
        # 3.密碼長度
        if len(password) < 8:
            flash("密碼長度不能小於8")
            return redirect(url_for("register"))
        # 4.密碼要有大寫、小寫、數字
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$", password):
            flash("密碼要有大寫、小寫、數字")
            return redirect(url_for("register"))
        # 檢查帳號是否已被註冊
        if collection.find_one({"email": email}):
            flash("檢查帳號是否已被註冊")
            return redirect(url_for("register"))
        # 插入新使用者資料到 MongoDB
        collection.insert_one({"email": email, "password": password})
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


# 登錄頁面
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.honeypot.data:
            return "Bot detected!", 400
        # 表單提取帳號密碼
        email = form.email.data
        password = form.password.data
        # 驗證格式
        # 2.gmail格式
        if not re.match(r"^[a-zA-Z0-9_.+-]+@gmail\.com$", email):
            session["error_msg"] = "帳號格式錯誤"
            return redirect(url_for("error"))  # 錯誤頁面
        # 兩個都不能為空
        if not email or not password:
            session["error_msg"] = "帳號或密碼不能為空"
            return redirect(url_for("error"))
        # 驗證帳號密碼
        user = collection.find_one({"email": email, "password": password})
        # 帳號密碼正確
        if user and user["password"] == password:
            # 登錄成功，導向在校成員頁面，並設定session
            return redirect(url_for("member"))
        # 帳號密碼錯誤
        else:
            session["error_msg"] = "帳號或密碼錯誤"
            return redirect(url_for("error"))

    return render_template("login.html", form=form)


# 忘記密碼頁面
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        # 在這裡查找用戶並生成重設密碼的連結
        token = "some_unique_token"  # 生成一個唯一的 token
        reset_url = url_for("reset_password", token=token, _external=True)
        send_email(email, "重設密碼", f"請點擊以下連結重設密碼：{reset_url}")
        flash("重設密碼的郵件已發送到您的郵箱。")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


# 重設密碼頁面
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        password = request.form["password"]
        # 在這裡更新用戶的密碼
        flash("密碼已成功重設。")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


# 錯誤頁面
@app.route("/error")
def error():
    error_message = session.pop("error_msg", None)
    return render_template("error.html", error_message=error_message)


# 在校成員頁面
@app.route("/member")
def member():
    return render_template("member.html")


# 隱私權政策
@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


# json格式
@app.route("/fetch_data")
def fetch_data():
    response = requests.get("https://website-jjt5.onrender.com/register")

    if response.status_code == 200:
        if response.headers.get("Content-Type") == "application/json":
            try:
                data = response.json()
                return jsonify(data)
            except json.JSONDecodeError as e:
                print(f"JSONDecodeError: {e}")
                return jsonify({"error": "Invalid JSON response"}), 500
        else:
            print(f"Unexpected content type: {response.headers.get('Content-Type')}")
            return jsonify({"error": "Unexpected content type"}), 500
    else:
        print(f"Request failed with status code {response.status_code}")
        return jsonify({"error": "Request failed"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)  # 啟動伺服器
