import io
import os
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from compiler.c_cpp_lexer import build_c_lexer
from compiler.c_cpp_parser import c_parser
from compiler.semantic import SemanticAnalyzer
from compiler.transcompiler import get_all_conversions, transcompile
from security.c_cpp_engine import CCppSecurityEngine
from security.python_engine import analyze_python_code
from security.java_engine import analyze_java_code
from security.risk_evaluator import calculate_risk_profile
from auth import init_db, User

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB upload limit

SUPPORTED_LANGUAGES = {
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "python": "python",
    "py": "python",
    "java": "java",
}

init_db()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'


def normalize_language(language):
    if not language or not isinstance(language, str):
        return None
    return SUPPORTED_LANGUAGES.get(language.strip().lower())


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.authenticate(username, password)
        if user:
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('All fields are required.', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
        elif User.register(username, password):
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists.', 'error')
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def run_c_cpp_pipeline(code, is_cpp=False):
    lexer = build_c_lexer()
    lexer.input(code)
    tokens_list = []
    while True:
        tok = lexer.token()
        if not tok:
            break
        tokens_list.append({"type": tok.type, "value": str(tok.value), "line": tok.lineno})

    if lexer.errors:
        return {"success": False, "errors": lexer.errors, "stage": "Lexical Analysis"}

    c_parser.errors = []
    parse_lexer = build_c_lexer()
    parse_lexer.lineno = 1
    ast = c_parser.parse(code, lexer=parse_lexer, tracking=True)
    if c_parser.errors:
        return {"success": False, "errors": c_parser.errors, "stage": "Syntax Analysis"}

    semantic = SemanticAnalyzer()
    symbols, sem_errors = semantic.analyze(ast)
    if sem_errors:
        return {"success": False, "errors": sem_errors, "stage": "Semantic Analysis"}

    source_lines = code.splitlines()
    sec_engine = CCppSecurityEngine(ast, symbols, source_lines, is_cpp=is_cpp)
    findings, risk_profile = sec_engine.analyze()

    symbol_data = [
        {"name": s.name, "type": s.data_type, "scope": s.scope, "line": s.line, "init": s.initialized}
        for s in symbols
    ]

    src_lang = "cpp" if is_cpp else "c"
    translations = get_all_conversions(code, src_lang)

    return {
        "success": True,
        "language": "C++" if is_cpp else "C",
        "tokens": tokens_list,
        "ast": ast.to_dict() if ast else {},
        "symbols": symbol_data,
        "findings": findings,
        "risk_profile": risk_profile,
        "translations": translations
    }


def run_pipeline(code, language=None):
    if not language:
        return {
            "success": False,
            "errors": ["Please select a programming language (C, C++, Python, or Java) before analyzing."],
            "stage": "Language Selection"
        }

    lang = normalize_language(language)
    if lang == "c":
        return run_c_cpp_pipeline(code, is_cpp=False)
    elif lang == "cpp":
        return run_c_cpp_pipeline(code, is_cpp=True)
    elif lang == "python":
        res = analyze_python_code(code)
        res["language"] = "Python"
        if res.get("success"):
            res["translations"] = get_all_conversions(code, "python")
        return res
    elif lang == "java":
        res = analyze_java_code(code)
        res["language"] = "Java"
        if res.get("success"):
            res["translations"] = get_all_conversions(code, "java")
        return res
    else:
        return {
            "success": False,
            "errors": [f"Unsupported target language '{language}'. Please select C, C++, Python, or Java."],
            "stage": "Language Selection"
        }


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    code = ""
    snapshot_id = ""
    data = request.get_json(silent=True) or {}
    language = request.form.get('language') or data.get('language')

    if 'file' in request.files and request.files['file'].filename != '':
        f = request.files['file']
        ext = os.path.splitext(f.filename)[1].lower()
        if not language:
            if ext == '.c':
                language = 'c'
            elif ext in ['.cpp', '.cc', '.cxx', '.h', '.hpp']:
                language = 'cpp'
            elif ext == '.py':
                language = 'python'
            elif ext == '.java':
                language = 'java'
            else:
                return jsonify({
                    "success": False,
                    "errors": ["Unsupported file type. Please upload a .c, .cpp, .java, or .py source file."]
                }), 400
        code = f.read().decode('utf-8', errors='replace')
    else:
        source_payload = data if data else request.form
        code = source_payload.get('code', '')
        snapshot_id = str(source_payload.get('snapshot_id', ''))

    normalized_lang = normalize_language(language)
    if not normalized_lang:
        return jsonify({
            "success": False,
            "errors": ["Please select a valid target programming language (C, C++, Python, or Java) first."]
        }), 400

    if not isinstance(code, str) or not code.strip():
        return jsonify({
            "success": False,
            "errors": ["Input code is empty. Please enter or upload code to analyze."]
        }), 400

    result = run_pipeline(code, language=normalized_lang)
    if result.get("success"):
        result["workspace_meta"] = {
            "analyzed_language": result.get("language"),
            "line_count": len(code.splitlines()),
            "snapshot_id": snapshot_id
        }
    return jsonify(result)


@app.route('/export-pdf', methods=['POST'])
@login_required
def export_pdf():
    data = request.get_json(force=True)
    findings = data.get('findings', [])
    language = data.get('language', 'General')
    risk = data.get('risk_profile') or calculate_risk_profile(findings)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor('#0F172A'), spaceAfter=4)
    meta_style = ParagraphStyle('DocMeta', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748B'))
    story.append(Paragraph(f"Secure Compiler — {language} Vulnerability & Risk Audit", title_style))
    story.append(Paragraph(f"Auditor: <b>{current_user.username}</b> &nbsp;|&nbsp; Target Language: <b>{language}</b> &nbsp;|&nbsp; Static AST & High-to-High Engine", meta_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#E2E8F0'), spaceBefore=2, spaceAfter=12))

    risk_color_hex = risk.get('pdf_color', '#10B981')
    risk_banner_data = [
        [
            Paragraph(f"<font size=11 color='#FFFFFF'><b>OVERALL PROGRAM RISK EVALUATION</b></font>", styles['Normal']),
            Paragraph(f"<font size=13 color='#FFFFFF'><b>{risk.get('level', 'CLEAN')} ({risk.get('score', 0)}/100)</b></font>", styles['Normal'])
        ],
        [
            Paragraph(f"<font size=9 color='#FFFFFF'>{risk.get('summary', '')}</font>", styles['Normal']),
            Paragraph(f"<font size=9 color='#FFFFFF'>High: {risk.get('counts', {}).get('HIGH', 0)} | Med: {risk.get('counts', {}).get('MEDIUM', 0)} | Total: {risk.get('total_findings', 0)}</font>", styles['Normal'])
        ]
    ]
    banner_table = Table(risk_banner_data, colWidths=[340, 200])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(risk_color_hex)),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 15))

    heading2 = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=12, textColor=colors.HexColor('#1E293B'), spaceBefore=6, spaceAfter=6)
    story.append(Paragraph("Identified Vulnerable Lexemes & Weak Points", heading2))

    if not findings:
        clean_box = Table([[Paragraph("<font size=10 color='#065F46'>No vulnerabilities detected! The code parsed and compiled cleanly without triggering any known threat rules.</font>", styles['Normal'])]], colWidths=[540])
        clean_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ECFDF5')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#A7F3D0')),
            ('PADDING', (0, 0), (-1, -1), 10)
        ]))
        story.append(clean_box)
    else:
        table_data = [["Rule ID", "Sev.", "Line", "Vulnerable Lexeme", "Weak Point & Solution"]]
        for f in findings:
            sev_color = "#DC2626" if f['severity'] == "HIGH" else ("#D97706" if f['severity'] == "MEDIUM" else "#2563EB")
            table_data.append([
                f['rule_id'],
                Paragraph(f"<font color='{sev_color}'><b>{f['severity']}</b></font>", styles['Normal']),
                str(f['line']),
                Paragraph(f"<font face='Courier' size=8 color='#B91C1C'><b>{f.get('lexeme', 'N/A')}</b></font><br/><font size=7 color='#64748B'>{f['evidence']}</font>", styles['Normal']),
                Paragraph(f"<b>{f['title']}</b><br/><font size=8><b>Explanation:</b> {f['description']}</font><br/><font size=7 color='#047857'><b>Solution:</b> {f['recommendation']}</font>", styles['Normal'])
            ])

        t = Table(table_data, colWidths=[55, 45, 30, 160, 250])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')])
        ]))
        story.append(t)

    doc.build(story)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"secure_compiler_{language}_audit.pdf", mimetype='application/pdf')


if __name__ == '__main__':
    app.run(debug=True, port=5000)