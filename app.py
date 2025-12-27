from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from peewee import *
from flask_bcrypt import Bcrypt
import datetime
import os
from functools import wraps
from functools import reduce
import operator

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
bcrypt = Bcrypt(app)

db = SqliteDatabase('robot.sqlite')

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    account = CharField(unique=True)
    password = CharField()

class Program(BaseModel):
    time = DateTimeField(default=datetime.datetime.now)
    user = ForeignKeyField(User, backref='programs')
    code = TextField()          # 統一儲存程式碼
    type = CharField(default='brython')  # 'brython' 或 'pyodide'
    from_where = CharField(default='web')
    memo = TextField(null=True)
    desp = TextField(null=True)

db.connect()
db.create_tables([User, Program], safe=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("請先登入才能執行此操作")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==============================
# 路由
# ==============================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        account = request.form['account'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if not (len(account) == 8 and account.isdigit()):
            flash("學號必須是 8 位數字！")
            return redirect(url_for('register'))
        if password != confirm_password:
            flash("兩次密碼不一致！")
            return redirect(url_for('register'))
        if User.select().where(User.account == account).exists():
            flash("此學號已被註冊！")
            return redirect(url_for('register'))
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        User.create(account=account, password=hashed_pw)
        flash("註冊成功！請登入")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        account = request.form['account'].strip()
        password = request.form['password']
        try:
            user = User.get(User.account == account)
        except User.DoesNotExist:
            flash("帳號或密碼錯誤")
            return redirect(url_for('login'))
        if bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("登入成功！")
            return redirect(url_for('brython_test'))
        else:
            flash("帳號或密碼錯誤")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("已成功登出")
    return redirect(url_for('index'))

# ==============================
# 編輯器頁面（不需登入即可使用）
# ==============================

@app.route('/brython_test')
def brython_test():
    if 'user_id' not in session:
        return render_template('brython_test_not_login.html')
    else:
        return render_template('brython_test.html')

@app.route('/pyodide_test')
def pyodide_test():
    if 'user_id' not in session:
        return render_template('pyodide_test_not_login.html')
    else:
        return render_template('pyodide_test.html')

# ==============================
# 儲存程式（必須登入）
# ==============================
@app.route('/save_program', methods=['POST'])
@login_required
def save_program():
    data = request.get_json()
    code = data.get('code', '').strip()
    prog_type = data.get('type', 'brython')
    desp = data.get('desp', '').strip()

    if not code:
        return jsonify({"message": "程式碼不能為空"}), 400

    try:
        user = User.get(User.id == session['user_id'])
        program = Program.create(
            user=user,
            code=code,
            type=prog_type,
            from_where='',
            memo='',
            desp=desp
        )
        return jsonify({
            "message": "程式碼與描述已儲存到資料庫！",
            "id": program.id,
            "desp": program.desp
        }), 200
    except Exception as e:
        return jsonify({"message": f"儲存失敗: {str(e)}"}), 500

# ==============================
# 載入程式：根據 type 跳轉（不需登入）
# ==============================
@app.route('/load_program/<int:program_id>')
def load_program(program_id):
    try:
        program = Program.get(Program.id == program_id)
        if program.type == 'pyodide':
            return redirect(f"{url_for('pyodide_test')}?load={program_id}")
        else:
            return redirect(f"{url_for('brython_test')}?load={program_id}")
    except Program.DoesNotExist:
        flash("程式不存在")
        return redirect(url_for('programs'))

# ==============================
# API：取得單一程式（不需登入即可讀取）
# ==============================
@app.route('/api/program/<int:program_id>')
def api_get_program(program_id):
    try:
        program = Program.get(Program.id == program_id)
        return jsonify({
            'code': program.code,
            'type': program.type,
            'desp': program.desp or ''
        })
    except Program.DoesNotExist:
        return jsonify({'error': 'Not found'}), 404

# ==============================
# 程式清單（不需登入即可瀏覽）
# ==============================
@app.route('/programs')
def programs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    total_programs = Program.select().count()
    total_pages = (total_programs + per_page - 1) // per_page
    has_next = page < total_pages
    has_prev = page > 1

    programs = Program.select() \
        .order_by(Program.time.desc()) \
        .paginate(page, per_page) \
        .join(User)

    return render_template('programs.html',
                           programs=programs,
                           page=page,
                           total_pages=total_pages,
                           has_next=has_next,
                           has_prev=has_prev,
                           per_page=per_page)

# ==============================
# 搜尋程式（不需登入即可搜尋）
# ==============================
@app.route('/search_programs')
def search_programs():
    q = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 5

    base = Program.select(Program, User.account).join(User)
    if q:
        conditions = [
            User.account.contains(q),
            Program.code.contains(q),
            Program.from_where.contains(q),
            Program.memo.contains(q),
            Program.desp.contains(q),
            Program.type.contains(q)
        ]
        base = base.where(reduce(operator.or_, conditions))

    total = base.count()
    total_pages = (total + per_page - 1) // per_page
    has_next = page < total_pages
    has_prev = page > 1

    programs = base.order_by(Program.time.desc()).paginate(page, per_page)

    result = []
    for p in programs:
        result.append({
            'id': p.id,
            'time': p.time.strftime('%Y-%m-%d %H:%M'),
            'account': p.user.account,
            'type': p.type,
            'code_snippet': (p.code or '')[:70].replace('\n', ' ') + ('...' if len(p.code or '') > 70 else ''),
            'from_where': p.from_where or '',
            'memo': (p.memo or '')[:40] + ('...' if p.memo and len(p.memo) > 40 else ''),
            'desp': (p.desp or '')[:50] + ('...' if p.desp and len(p.desp) > 50 else ''),
        })

    return jsonify({
        'programs': result,
        'page': page,
        'total_pages': total_pages,
        'has_next': has_next,
        'has_prev': has_prev,
        'total': total
    })

if __name__ == '__main__':
    app.run(debug=True)