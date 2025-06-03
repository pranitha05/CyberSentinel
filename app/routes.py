from flask import Blueprint, render_template, request
from .password_checker import check_password_strength
from .hibp_checker import check_password_breach

main = Blueprint('main', __name__)

# Homepage
@main.route('/')
def index():
    return render_template('index.html')

# Password Strength Checker page
@main.route('/password-checker', methods=['GET', 'POST'])
def password_checker():
    result = None
    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            result = check_password_strength(password)
            result['password'] = password
    return render_template('password_checker.html', result=result)

# Breach Checker page
@main.route('/breach-checker', methods=['GET', 'POST'])
def breach_checker():
    breach_result = None
    password = None
    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            breach_result = check_password_breach(password)
    return render_template('breach_checker.html', result=breach_result, password=password)

# Coming Soon pages
@main.route('/network-scanner')
def network_scanner():
    return render_template('network_scanner.html')

@main.route('/encryption-tools')
def encryption_tools():
    return render_template('encryption_tools.html')

@main.route('/privacy-analyzer')
def privacy_analyzer():
    return render_template('privacy_analyzer.html')
