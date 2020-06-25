#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: matamorphosis
# License: GPL-3.0

if __name__ == '__main__':
    from flask import Flask, render_template, json, request, redirect, url_for, session, send_from_directory, jsonify
    from flask_compress import Compress
    from signal import signal, SIGINT
    from functools import wraps
    from datetime import datetime, timedelta
    from werkzeug.security import generate_password_hash, check_password_hash
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from crontab import CronTab
    from logging.handlers import RotatingFileHandler
    from ratelimiter import RateLimiter
    import os, re, plugin_caller, getpass, time, sys, threading, html, secrets, jwt, plugins.common.Connectors as Connectors, plugins.common.General as General, logging

    Valid_Plugins = ["Ahmia Darkweb Search", "Blockchain Bitcoin Address Search", "Blockchain Bitcoin Cash Address Search", "Blockchain Ethereum Address Search", "Blockchain Bitcoin Transaction Search", "Blockchain Bitcoin Cash Transaction Search", "Blockchain Ethereum Transaction Search", "Blockchain Monero Transaction Search", "BSB Search", "Business Search - American Central Index Key", "Business Search - American Company Name", "Business Search - Australian Business Number", "Business Search - Australian Company Name", "Business Search - Canadian Business Number", "Business Search - Canadian Company Name", "Business Search - New Zealand Business Number", "Business Search - New Zealand Company Name", "Business Search - United Kingdom Business Number", "Business Search - United Kingdom Company Name", "Certificate Transparency", "Craigslist Search", "Default Password Search", "DNS Reconnaissance Search", "Domain Fuzzer - All Extensions",
                     "Domain Fuzzer - Punycode", "Domain Fuzzer - Global Domain Suffixes", "Domain Fuzzer - Regular Domain Suffixes", "Ebay Search", "Flickr Search", "Google Search", "Have I Been Pwned - Password Search",
                     "Have I Been Pwned - Email Search", "Have I Been Pwned - Breach Search", "Have I Been Pwned - Account Search", "Instagram Location Search", "Instagram Media Search", "Instagram Tag Search", "Instagram User Search", "iTunes Store Search", "Library Genesis Search", "PhishTank Search", "Google Play Store Search", "Pinterest Board Search", "Pinterest Pin Search", "Reddit Search", "RSS Feed Search", "Torrent Search", "Twitter Scraper", "Vehicle Registration Search", "Vulners Search", "Windows Store Search", "YouTube Search"]
    Plugins_without_Limit = ["BSB Search", "Blockchain Monero Transaction Search", "Business Search - American Central Index Key", "Business Search - Australian Business Number", "Business Search - Canadian Business Number", "Business Search - New Zealand Business Number", "Business Search - United Kingdom Business Number", "Certificate Transparency", "DNS Reconnaissance Search", "Domain Fuzzer - All Extensions", "Domain Fuzzer - Alpha-Linguistic Character Switcher", "Domain Fuzzer - Global Domain Suffixes", "Domain Fuzzer - Regular Domain Suffixes", "Have I Been Pwned - Email Search", "Have I Been Pwned - Breach Search", "Have I Been Pwned - Password Search", "Instagram Media Search", "Pinterest Pin Search", "Vehicle Registration Search"]
    API_Plugins = ["Business Search - United Kingdom Business Number", "Business Search - United Kingdom Company Name", "Certificate Transparency", "Craigslist Search", "Ebay Search", "Flickr Search", "Google Search", "Pinterest Board Search", "Pinterest Pin Search", "Reddit Search", "Twitter Scraper", "Vulners Search", "YouTube Search"]
    Phishing_Sites = [["All", "All"], [139, "ABL"], [201, "ABN"], [92, "ABSA Bank"], [68, "Accurint"], [207, "Adobe"], [209, "Aetna"], [211, "Alibaba.com"], [160, "Allegro"], [51, "Alliance Bank"], [28, "Amarillo"], [61, "Amazon.com"], [118, "American Airlines"], [184, "American Express"], [141, "American Greetings"], [15, "Ameritrade"], [133, "ANZ"], [110, "AOL"], [183, "Apple"], [170, "ArenaNet"], [144, "ASB"], [17, "Associated Bank"], [189, 'AT&T'], [165, "ATO"], [249, "B-tc.ws"], [73, "Banca di Roma"], [178, "Banca Intesa"], [124, "Bancasa"], [158, "Banco De Brasil"], [125, "Banco Real"], [208, "Bank Millennium"], [6, "Bank of America / MBNA"], [40, "Bank of KC"], [45, "Bank of the West"], [5, "Barclays"], [63, "BB&amp;T"], [27, "Bendigo"], [226, "Binance"], [217, "Bitfinex"], [224, "bitFlyer"], [229, "Bitmex"], [122, "Blizzard"], [210, "Blockchain"], [96, "BloomSpot"], [44, "BMO"], [82, "Bradesco"], [212, "BT"], [98, "BuyWithMe"], [126, "Cahoot"], [138, "Caixa"], [120, "Caixo"], [29, "Capital One"], [156, "Capitec Bank"], [65, "Career Builder"], [105, "Cariparma Credit Agricole"], [107, "Cartasi"], [131, "Centurylink"], [19, "Charter One"], [3, "Chase"], [32, "CIBC"], [137, "Cielo"], [150, "CIMB Bank"], [42, "Citibank"], [14, "Citizens"], [230, "CNB"], [146, "Co-operative Bank"], [214, "Coinbase"], [22, "Comerica"], [167, "Commonwealth Bank of Australia"], [30, "Compass"], [113, "Craigslist"], [219, "Credit Karma"], [31, "Crown"], [87, "CUA (Credit Union Australia)"], [33, "DBS"], [140, "Delta"], [185, "Deutsche Bank"], [197, "DHL"], [188, "Diners Club"], [187, "Discover Bank"], [186, "Discover Card"], [196, "Discovery"], [60, "Downey Savings"], [194, "Dropbox"], [59, "e-gold"], [2, "eBay"], [102, "Egg"], [77, "EPPICard"], [74, "Facebook"], [41, "FHB"], [48, "Fifth Third Bank"], [103, "First Direct"], [50, "First Federal Bank of California"], [91, "First National Bank (South Africa)"], [39, "Franklin"], [218, "GitHub"], [76, "Google"], [94, "Groupon"], [106, "Gruppo Carige"], [151, "GTBank"], [171, "GuildWars2"], [81, "Habbo"], [104, "Halifax"], [108, "HMRC"], [97, "HomeRun"], [154, "Hotmail"], [4, "HSBC"], [18, "Huntington"], [228, "IDEX"], [57, "Independent Bank"], [123, "ING"], [67, "Interactive Brokers"], [202, "Intesa Sanpaolo"], [62, "IRS"], [135, "Itau"], [72, "KCFCU (Kauai Credit Union)"], [20, "Key Bank"], [203, "Kiwibank"], [9, "LaSalle"], [204, "LinkedIn"], [152, "Littlewoods"], [112, "Live"], [95, "LivingSocial"], [182, "Lloyds Bank"], [215, "LocalBitcoins.com"], [179, "Lottomatica"], [12, "M &amp; I"], [130, "Mastercard"], [66, "MBTrading"], [173, "Metro Bank"], [177, "Microsoft"], [227, "MyCrypto"], [223, "MyEtherWallet"], [225, "MyMonero"], [78, "MySpace"], [164, "NAB"], [37, "Nantucket Bank"], [34, "National City"], [148, "Nationwide"], [26, "NatWest"], [71, "Nedbank"], [200, "Netflix"], [161, "Nets"], [205, "NetSuite"], [127, "NEXON"], [175, "Nordea"], [149, "Northern Rock"], [168, "Orange"], [89, "Orkut"], [8, "Other"], [159, "otoMoto"], [192, "PagSeguro"], [216, "Paxful"], [1, "PayPal"], [23, "Peoples"], [195, "Permanent TSB"], [180, "Pintrest"], [176, "PKO"], [114, "Playdom"], [115, "Playfish"], [100, "Plum District"], [69, "PNC Bank"], [64, "Poste"], [128, "Rabobank"], [221, "Rackspace"], [36, "RBC"], [70, "RBS"], [16, "Regions"], [134, "RuneScape"], [121, "Safra National Bank of New York"], [35, "Salem Five"], [75, "Salesforce"], [109, "Santander UK"], [84, "Scotiabank"], [55, "Sky Financial"], [117, "Skype"], [147, "Smile Bank"], [93, "South African Revenue Service"], [166, "St George Bank"], [90, "Standard Bank Ltd."], [86, "Steam"], [163, "Suncorp"], [172, "Swedbank"], [145, "Tagged"], [136, "TAM Fidelidade"], [43, "TD Canada Trust"], [193, "Tesco"], [85, "Tibia"], [99, "Tippr"], [181, "TSB"], [132, "Twitter"], [213, "Uber"], [220, "UniCredit"], [157, "US Airways"], [24, "US Bank"], [199, "USAA"], [169, "Verizon"], [153, "Very"], [248, "Virustotal"], [129, "Visa"], [155, "Vodafone"], [58, "Volksbanken Raiffeisenbanken"], [13, "Wachovia"], [56, "WalMart"], [21, "Washington Mutual"], [7, "Wells Fargo"], [53, "Western Union"], [25, "Westpac"], [206, "WhatsApp"], [88, "World of Warcraft"], [222, "Xapo"], [111, "Yahoo"], [116, "ZML"], [101, "Zynga"]]
    Bad_Characters = ["|", "&", "?", "\\", "\"", "\'", "[", "]", ">", "<", "~", "`", ";", "{", "}", "%", "^", "--", "++", "+", "'", "(", ")", "*", "="]
    Finding_Types = ['Domain Spoof', 'Data Leakage', 'Phishing', 'Blockchain Transaction', 'Blockchain Address', 'Exploit']
    Version = "2.3"

    try:
        File_Path = os.path.dirname(os.path.realpath('__file__'))
        app = Flask(__name__, instance_path=os.path.join(File_Path, 'static/protected'))
        Compress(app)
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Strict',
        )
        app.permanent_session_lifetime = timedelta(minutes=5)

    except:
        app.logger.fatal(f'{General.Date()} Startup error, ensure all necessary libraries are imported and installed.')
        sys.exit()

    def Load_Web_App_Configuration():

        try:
            File_Dir = os.path.dirname(os.path.realpath('__file__'))
            Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
            logging.info(f"{General.Date()} Loading web application's configuration data.")

            with open(Configuration_File) as JSON_File:
                Configuration_Data = json.load(JSON_File)
                WA_Details = Configuration_Data['web-app']
                WA_Debug = WA_Details['debug']
                WA_Host = WA_Details['host']
                WA_Port = WA_Details['port']
                WA_Cert_File = WA_Details['certificate-file']
                WA_Key_File = WA_Details['key-file']
                WA_API_Secret = WA_Details['api-secret']
                WA_API_Validity_Limit = int(WA_Details['api-validity-minutes'])
                WA_API_Max_Calls = int(WA_Details['api-max-calls'])
                WA_API_Period = int(WA_Details['api-period-in-seconds'])

            if WA_API_Validity_Limit < 60:
                sys.exit("[-] API Key Validity Limit too short. Minimum should be 60 minutes.")

            if WA_Host and WA_Port and WA_Cert_File and WA_Key_File and WA_API_Secret and WA_API_Validity_Limit and WA_API_Max_Calls and WA_API_Period:
                return [WA_Debug, WA_Host, WA_Port, WA_Cert_File, WA_Key_File, WA_API_Secret, WA_API_Validity_Limit, WA_API_Max_Calls, WA_API_Period]

            else:
                return None

        except Exception as e:
            logging.warning(f"{General.Date()} {str(e)}")
            sys.exit()

    Application_Details = Load_Web_App_Configuration()
    API_Secret = Application_Details[5]
    API_Validity_Limit = Application_Details[6]
    API_Max_Calls = Application_Details[7]
    API_Period = Application_Details[8]

    def handler(signal_received, frame):
        print('[i] CTRL-C detected. Shutting program down.')
        Connection.close()
        sys.exit()

    signal(SIGINT, handler)
    formatter = logging.Formatter("[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
    handler = RotatingFileHandler('Scrummage.log', maxBytes=10000, backupCount=5)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.secret_key = os.urandom(24)

    try:
        Connection = Connectors.Load_Main_Database()
        Cursor = Connection.cursor()

    except:
        app.logger.fatal(f'{General.Date()} Failed to load main database, please make sure the database details are added correctly to the configuration.')
        sys.exit()

    try:
        Cursor.execute('UPDATE tasks SET status = %s', ("Stopped",))
        Connection.commit()

    except:
        app.logger.fatal(f'{General.Date()} Startup error - database issue.')
        sys.exit()

    try:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(certfile=Application_Details[3], keyfile=Application_Details[4])

    except:
        app.logger.fatal(f'{General.Date()} Error initiating SSL.')
        sys.exit()

    class User:

        def __init__(self, username, password):
            self.username = username
            self.password = password

        def authenticate(self):
            Cursor.execute('SELECT * FROM users WHERE username = %s', (self.username,))
            User_Details = Cursor.fetchone()

            if User_Details:
                Password_Check = check_password_hash(User_Details[2], self.password)

                if not Password_Check:

                    for char in self.password:

                        if char in Bad_Characters:
                            Message = f"Failed login attempt for the provided user ID {str(User_Details[0])} with a password that contains potentially dangerous characters."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Message": True}

                    Message = f"Failed login attempt for user {str(User_Details[0])}."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return {"Message": True}

                else:

                    if not User_Details[3]:
                        self.ID = User_Details[0]
                        self.authenticated = True
                        self.admin = User_Details[4]
                        self.API = User_Details[5]
                        return {"ID": self.ID, "Username": User_Details[1], "Admin": self.admin, "API": self.API, "Status": True}

                    else:
                        Message = f"Login attempted by user ID {str(User_Details[0])} who is currently blocked."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        return {"Message": True}

            else:

                for char in self.username:

                    if char in Bad_Characters:
                        Message = "Failed login attempt for a provided username that contained potentially dangerous characters."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        return {"Message": True}

                    else:
                        Message = f"Failed login attempt for user {self.username}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        return {"Message": True}

        def API_registration(self):

            def Create_JWT(self):
                Expiry_Hours = API_Validity_Limit / 60
                Expiry = datetime.utcnow() + timedelta(hours=Expiry_Hours)
                payload = {"id": self.ID, "name": self.username, "iat": datetime.utcnow(), "exp": Expiry, "nonce": secrets.token_hex(32)}
                JWT = jwt.encode(payload, API_Secret, algorithm='HS256')
                return JWT.decode('utf-8')

            if 'authenticated' in dir(self):

                try:
                    Decoded_Token = jwt.decode(self.API, API_Secret, algorithm='HS256')
                    return {"Key": self.API, "Message": "Current API is still valid."}

                except jwt.ExpiredSignatureError:
                    API_Key = Create_JWT(self)
                    Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, General.Date(), self.ID,))
                    Connection.commit()
                    Message = f"New API Key generated for user ID {str(self.ID)}."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return {"Key": API_Key, "Message": Message}

                except jwt.DecodeError:
                    return {"Key": None, "Message": "Failed to verify token."}

                except jwt.InvalidTokenError:
                    return {"Key": None, "Message": "Failed to verify token."}

            else:
                return {"Key": None, "Message": "Unauthorised."}

    def API_verification(auth_token):

        try:
            Decoded_Token = jwt.decode(auth_token, API_Secret, algorithm='HS256')
            User_ID = int(Decoded_Token['id'])
            Cursor.execute('SELECT * FROM users WHERE user_id = %s', (User_ID,))
            User_Details = Cursor.fetchone()

            if auth_token == User_Details[5]:
                return {"Token": True, "Admin": User_Details[4], "Message": "Token verification successful."}

            else:
                return {"Token": False, "Admin": False, "Message": "Invalid token."}

        except jwt.ExpiredSignatureError:
            return {"Token": False, "Admin": False, "Message": "Token expired."}

        except jwt.DecodeError:
            return {"Token": False, "Admin": False, "Message": "Failed to decode token."}

        except jwt.InvalidTokenError:
            return {"Token": False, "Admin": False, "Message": "Invalid token."}

    def Output_API_Checker(Plugin_Name):

        try:

            if Plugin_Name in API_Plugins:

                if Plugin_Name == API_Plugins[0] or Plugin_Name == API_Plugins[1]:
                    import plugins.UK_Business_Search as UK_Business_Search
                    Result = UK_Business_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[2]:
                    import plugins.Certificate_Transparency as Certificate_Transparency
                    Result = Certificate_Transparency.Load_Configuration()

                elif Plugin_Name == API_Plugins[3]:
                    import plugins.Craigslist_Search as Craigslist_Search
                    Result = Craigslist_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[4]:
                    import plugins.Ebay_Search as Ebay_Search
                    Result = Ebay_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[5]:
                    import plugins.Flickr_Search as Flickr_Search
                    Result = Flickr_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[6]:
                    import plugins.Google_Search as Google_Search
                    Result = Google_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[7] or Plugin_Name == API_Plugins[8]:
                    import plugins.Pinterest_Search as Pinterest_Search
                    Result = Pinterest_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[9]:
                    import plugins.Reddit_Search as Reddit_Search
                    Result = Reddit_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[10]:
                    import plugins.Twitter_Scraper as Twitter_Scraper
                    Result = Twitter_Scraper.Load_Configuration()

                elif Plugin_Name == API_Plugins[11]:
                    import plugins.Vulners_Search as Vulners_Search
                    Result = Vulners_Search.Load_Configuration()

                elif Plugin_Name == API_Plugins[12]:
                    import plugins.YouTube_Search as YouTube_Search
                    Result = YouTube_Search.Load_Configuration()

                if Result:
                    return "Passed"

                else:
                    return "Failed"

            else:
                return "N/A"

        except Exception as e:
            app.logger.error(e)

    def Create_Event(Description):

        try:
            Cursor.execute("INSERT INTO events (description, created_at) VALUES (%s,%s)", (Description, General.Date()))
            Connection.commit()

        except Exception as e:
            app.logger.error(e)

    @app.errorhandler(404)
    def page_not_found(e):

        try:
            return render_template('404.html', username=session.get('user')), 404

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('index'))

    @app.errorhandler(405)
    @app.route('/nomethod')
    def no_method(e):

        try:
            return render_template('nomethod.html', username=session.get('user'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('index'))

    app.register_error_handler(404, page_not_found)
    app.register_error_handler(405, no_method)

    @app.route('/')
    def index():

        try:

            if session.get('user'):
                return redirect(url_for('dashboard'))

            else:
                return render_template('index.html')

        except Exception as e:
            app.logger.error(e)
            sys.exit("[-] Failed to initialise index.html file.")

    @app.route('/login', methods=['GET', 'POST'])
    def login():

        try:

            if request.method == 'POST':

                if 'username' in request.form and 'password' in request.form:

                    for char in request.form['username']:

                        if char in Bad_Characters:
                            return render_template('login.html', error="Login Unsuccessful.")

                    Current_User_Object = User(request.form['username'], request.form['password'])
                    Current_User = Current_User_Object.authenticate()

                    if 'Username' in Current_User and 'Status' in Current_User:
                        session['dashboard-refresh'] = 0
                        session['user_id'] = Current_User.get('ID')
                        session['user'] = Current_User.get('Username')
                        session['is_admin'] = Current_User.get('Admin')
                        session['api_key'] = Current_User.get('API')
                        session['form_step'] = 0
                        session['form_type'] = ""
                        session['task_frequency'] = ""
                        session['task_description'] = ""
                        session['task_limit'] = 0
                        session['task_query'] = ""
                        session['task_id'] = ""
                        Message = f"Successful login from {Current_User.get('Username')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                        if session.get("next_page"):
                            Redirect = session.get("next_page")
                            session["next_page"] == ""
                            return redirect(url_for(Redirect))

                        else:
                            return redirect(url_for('dashboard'))

                    elif 'Message' in Current_User:
                        return render_template('login.html', error='Login Unsuccessful.')

                    else:
                        return render_template('login.html')

                else:
                    return render_template('login.html')

            else:
                return render_template('login.html')

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('index'))

    @app.route('/api/v1/auth', methods=['POST'])
    @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
    def api_auth():

        try:

            if request.is_json:
                Content = request.get_json()

                if 'Username' in Content and 'Password' in Content:
                    Current_User_Object = User(Content['Username'], Content['Password'])
                    Current_User = Current_User_Object.authenticate()

                    if 'API' in Current_User:
                        Current_User_API = Current_User_Object.API_registration()

                        if "Key" in Current_User_API and "Message" in Current_User_API:
                            return jsonify({"Message": Current_User_API['Message'], "API Key": Current_User_API['Key']}), 200

                        else:
                            return jsonify({"Error": "Registration Unsuccessful"}), 500

                    elif 'Message' in Current_User:
                        return jsonify({"Error": "Registration Unsuccessful."}), 500

                else:
                    return jsonify({"Error": "Invalid fields in request."}), 500

            else:
                return jsonify({"Error": "Invalid request format."}), 500
            
        except Exception as e:
            app.logger.error(e)
            return jsonify({"Error": "Invalid request format."}), 500

    @app.route('/nosession')
    def no_session():

        try:
            return render_template('no_session.html')

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('index'))

    @app.route('/verify_output', methods=['POST', 'GET'])
    def verify_output():

        try:

            if session.get('user'):

                if session.get('is_admin'):
                    CSV = Connectors.Load_CSV_Configuration()
                    DD = Connectors.Load_Defect_Dojo_Configuration()
                    DOCX = Connectors.Load_DOCX_Configuration()
                    Email = Connectors.Load_Email_Configuration()
                    Elastic = Connectors.Load_Elasticsearch_Configuration()
                    Main_DB = Connectors.Load_Main_Database()
                    JIRA = Connectors.Load_JIRA_Configuration()
                    RTIR = Connectors.Load_RTIR_Configuration()
                    Slack = Connectors.Load_Slack_Configuration()
                    Scumblr = Connectors.Load_Scumblr_Configuration()
                    return render_template('verify_output.html', username=session.get('user'), Configurations=[["Main Database", Main_DB], ["CSV", CSV], ["DefectDojo", DD], ["DOCX", DOCX], ["Email", Email], ["ElasticSearch", Elastic], ["JIRA", JIRA], ["RTIR", RTIR], ["Slack Channel Notification", Slack], ["Scumblr Database", Scumblr]], is_admin=session.get('is_admin'))

                else:
                    return redirect(url_for('tasks'))

            else:
                session["next_page"] = "verify_output"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('tasks'))

    @app.route('/api/v1/verify_output', methods=['POST'])
    @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
    def api_verify_output():

        try:

            if 'Authorization' in request.headers:
                Auth_Token = request.headers['Authorization'].strip("Bearer ").strip("bearer ")
                Authentication_Verified = API_verification(Auth_Token)

                if Authentication_Verified["Token"]:

                    if Authentication_Verified["Admin"]:

                        if request.method == 'POST':
                            CSV = Connectors.Load_CSV_Configuration()
                            DD = Connectors.Load_Defect_Dojo_Configuration()
                            DOCX = Connectors.Load_DOCX_Configuration()
                            Email = Connectors.Load_Email_Configuration()
                            Elastic = Connectors.Load_Elasticsearch_Configuration()
                            Main_DB = Connectors.Load_Main_Database()
                            JIRA = Connectors.Load_JIRA_Configuration()
                            RTIR = Connectors.Load_RTIR_Configuration()
                            Slack = Connectors.Load_Slack_Configuration()
                            Scumblr = Connectors.Load_Scumblr_Configuration()

                            return jsonify([{"Main Database": bool(Main_DB)}, {"CSV": bool(CSV)}, {"DefectDojo": bool(DD)}, {".DOCX": bool(DOCX)}, {"Email": bool(Email)}, {"ElasticSearch": bool(Elastic)}, {"JIRA": bool(JIRA)}, {"RTIR": bool(RTIR)}, {"Slack Channel Notification": bool(Slack)}, {"Scumblr Database": bool(Scumblr)}]), 200

                        else:
                            return jsonify({"Error": "Method not allowed."}), 500

                    else:
                        return jsonify({"Error": "Insufficient privileges."}), 500

                else:

                    if Authentication_Verified["Message"]:
                        return jsonify({"Error": Authentication_Verified["Message"]}), 500

                    else:
                        return jsonify({"Error": "Unauthorised."}), 500

            else:
                return jsonify({"Error": "Missing Authorization header."}), 500

        except Exception as e:
            app.logger.error(e)
            return jsonify({"Error": "Unknown error."}), 500

    def requirement(f):

        try:
            @wraps(f)
            def wrap(*args, **kwargs):

                if session.get('user'):
                    return f(*args, **kwargs)

                else:
                    return redirect(url_for('no_session'))

            return wrap

        except Exception as e:
            app.logger.error(e)

    @app.route('/static/protected/<path:filename>')
    @requirement
    def protected(filename):

        try:
            return send_from_directory(os.path.join(app.instance_path, ''), filename)

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('results'))

    @app.after_request
    def apply_caching(response):

        try:
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["X-Content-Type"] = "nosniff"
            response.headers["Server"] = ""
            response.headers["Pragma"] = "no-cache"
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, pre-check=0, post-check=0, max-age=0, s-maxage=0"
            return response

        except Exception as e:
            app.logger.error(e)

    @app.route('/results/screenshot/<resultid>', methods=['POST'])
    def screenshot(resultid):

        try:
            Bad_Link_Strings = ['.onion', 'general-insurance.coles.com.au', 'magnet:?xt=urn:btih:']

            if session.get('user') and session.get('is_admin'):

                def grab_screenshot(screenshot_id, user, Chrome_Config):
                    Cursor.execute('SELECT link FROM results WHERE result_id = %s', (screenshot_id,))
                    result = Cursor.fetchone()
                    Cursor.execute('SELECT screenshot_url FROM results WHERE result_id = %s', (screenshot_id,))
                    SS_URL = Cursor.fetchone()
                    Cursor.execute('SELECT screenshot_requested FROM results WHERE result_id = %s', (screenshot_id,))
                    SS_Req = Cursor.fetchone()

                    if not SS_URL[0] and not SS_Req[0]:
                        Message = f"Screenshot requested for result number {str(screenshot_id)} by {user}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (True, screenshot_id,))
                        Connection.commit()

                        if any(String in result[0] for String in Bad_Link_Strings):
                            return redirect(url_for('results'))

                        screenshot_file = result[0].replace("http://", "")
                        screenshot_file = screenshot_file.replace("https://", "")

                        if screenshot_file.endswith('/'):
                            screenshot_file = screenshot_file[:-1]

                        if '?' in screenshot_file:
                            screenshot_file_list = screenshot_file.split('?')
                            screenshot_file = screenshot_file_list[0]

                        for replaceable_item in ['/', '?', '#', '&', '%', '$', '@', '*', '=']:
                            screenshot_file = screenshot_file.replace(replaceable_item, '-')

                        CHROME_PATH = Chrome_Config[0]
                        CHROMEDRIVER_PATH = Chrome_Config[1]
                        screenshot_file = f"{screenshot_file}.png"
                        chrome_options = Options()
                        chrome_options.add_argument("--headless")
                        chrome_options.binary_location = CHROME_PATH

                        try:
                            driver = webdriver.Chrome(
                                executable_path=CHROMEDRIVER_PATH,
                                options=chrome_options
                            )

                        except Exception as e:

                            if "session not created" in str(e):
                                e = str(e).strip('\n')
                                Message = f"Screenshot request terminated for result number {str(screenshot_id)} by application, please refer to the log."
                                Message_E = e.replace("Message: session not created: ", "")
                                Message_E = Message_E.replace("This version of", "The installed version of")
                                app.logger.warning(f"Screenshot Request Error: {Message_E}.")
                                app.logger.warning(f"Kindly replace the Chrome Web Driver, located at {Chrome_Config[1]}, with the latest one from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system.")
                                Create_Event(Message)
                                Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (False, screenshot_id,))
                                Connection.commit()
                            
                            return 0

                        driver.implicitly_wait(5)
                        driver.get(result[0])
                        total_height = driver.execute_script("return document.body.scrollHeight")
                        driver.set_window_size(1920, total_height)
                        driver.save_screenshot(f"static/protected/screenshots/{screenshot_file}")
                        driver.close()
                        Cursor.execute('UPDATE results SET screenshot_url = %s WHERE result_id = %s', (screenshot_file, screenshot_id,))
                        Connection.commit()

                    else:
                        app.logger.warning(f"Screenshot already requested for result id {str(ss_id)}.")

                ss_id = int(resultid)
                Chrome_Config = Connectors.Load_Chrome_Configuration()

                if all(os.path.exists(Config) for Config in Chrome_Config):
                    Thread_1 = threading.Thread(target=grab_screenshot, args=(ss_id, str(session.get('user')), Chrome_Config))
                    Thread_1.start()

                else:
                    app.logger.warning(f"Either Google Chrome or Chrome Driver have not been installed / configured. Screenshot request terminated.")                    

                return redirect(url_for('results'))

            else:
                session["next_page"] = "results"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('results'))

    @app.route('/dashboard', methods=['GET'])
    def dashboard():

        try:

            if session.get('user'):
                labels = Finding_Types
                colors = ["#2471A3", "#8B008B", "#DC143C", "#FFA500", "#DAFF00", "#00FF7F"]
                Mixed_Options = ['Inspecting', 'Reviewing']
                PSQL_Select_Query_1 = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
                PSQL_Select_Query_2 = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'

                Cursor.execute(PSQL_Select_Query_1, ("Open", "Domain Spoof",))
                open_domain_spoof_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Open", "Data Leakage",))
                open_data_leakages = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Open", "Phishing",))
                open_phishing_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Open", "Blockchain Transaction",))
                open_blockchain_transaction_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Open", "Blockchain Address",))
                open_blockchain_address_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Open", "Exploit",))
                open_exploit_results = Cursor.fetchall()

                Cursor.execute(PSQL_Select_Query_1, ("Closed", "Domain Spoof",))
                closed_domain_spoof_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Closed", "Data Leakage",))
                closed_data_leakages = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Closed", "Phishing",))
                closed_phishing_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Closed", "Blockchain Transaction",))
                closed_blockchain_transaction_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Closed", "Blockchain Address",))
                closed_blockchain_address_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_1, ("Closed", "Exploit",))
                closed_exploit_results = Cursor.fetchall()

                Cursor.execute(PSQL_Select_Query_2, ("Domain Spoof", Mixed_Options,))
                mixed_domain_spoof_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_2, ("Data Leakage", Mixed_Options,))
                mixed_data_leakages = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_2, ("Phishing", Mixed_Options,))
                mixed_phishing_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_2, ("Blockchain Transaction", Mixed_Options,))
                mixed_blockchain_transaction_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_2, ("Blockchain Address", Mixed_Options,))
                mixed_blockchain_address_results = Cursor.fetchall()
                Cursor.execute(PSQL_Select_Query_2, ("Exploit", Mixed_Options,))
                mixed_exploit_results = Cursor.fetchall()

                most_common_tasks_labels = []
                most_common_tasks_values = []
                Cursor.execute("SELECT plugin, COUNT(*) AS counted FROM tasks WHERE plugin IS NOT NULL GROUP BY plugin ORDER BY counted DESC, plugin LIMIT 10;")
                most_common_tasks = Cursor.fetchall()

                for mc_task in most_common_tasks:
                    most_common_tasks_labels.append(mc_task[0])
                    most_common_tasks_values.append(mc_task[1])

                open_values = [open_domain_spoof_results[0][0], open_data_leakages[0][0], open_phishing_results[0][0], open_blockchain_transaction_results[0][0], open_blockchain_address_results[0][0], open_exploit_results[0][0]]
                closed_values = [closed_domain_spoof_results[0][0], closed_data_leakages[0][0], closed_phishing_results[0][0], closed_blockchain_transaction_results[0][0], closed_blockchain_address_results[0][0], closed_exploit_results[0][0]]
                mixed_values = [mixed_domain_spoof_results[0][0], mixed_data_leakages[0][0], mixed_phishing_results[0][0], mixed_blockchain_transaction_results[0][0], mixed_blockchain_address_results[0][0], mixed_exploit_results[0][0]]

                if most_common_tasks:
                    return render_template('dashboard.html', username=session.get('user'), max=17000, open_set=zip(open_values, labels, colors), closed_set=zip(closed_values, labels, colors), mixed_set=zip(mixed_values, labels, colors), bar_labels=most_common_tasks_labels, bar_max=most_common_tasks_values[0], bar_values=most_common_tasks_values, refreshrate=session.get('dashboard-refresh'), version=Version)

                else:
                    return render_template('dashboard.html', username=session.get('user'), max=17000, open_set=zip(open_values, labels, colors), closed_set=zip(closed_values, labels, colors), mixed_set=zip(mixed_values, labels, colors), refreshrate=session.get('dashboard-refresh'), version=Version)

            else:
                session["next_page"] = "dashboard"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)

    @app.route('/dashboard/set-refresh', methods=['POST'])
    def dashboard_refresh():

        try:

            if session.get('user'):

                if 'setrefresh' in request.form and 'interval' in request.form:
                    approved_refresh_rates = [0, 5, 10, 15, 20, 30, 60]
                    refresh_rate = int(request.form['interval'])

                    if refresh_rate in approved_refresh_rates:
                        session['dashboard-refresh'] = refresh_rate
                        return redirect(url_for('dashboard'))

                    else:
                        return redirect(url_for('dashboard'))

                else:
                    return redirect(url_for('dashboard'))

            else:
                session["next_page"] = "dashboard"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)

    @app.route('/api/v1/dashboard', methods=['POST'])
    @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
    def api_dashboard():

        try:

            if 'Authorization' in request.headers:
                Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                Authentication_Verified = API_verification(Auth_Token)
                Mixed_Options = ['Inspecting', 'Reviewing']
                PSQL_Select_Query_1 = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
                PSQL_Select_Query_2 = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'

                if Authentication_Verified.get("Token"):
                    Cursor.execute(PSQL_Select_Query_1, ("Open", "Domain Spoof",))
                    open_domain_spoof_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Open", "Data Leakage",))
                    open_data_leakages = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Open", "Phishing",))
                    open_phishing_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Open", "Blockchain Transaction",))
                    open_blockchain_transaction_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Open", "Blockchain Address",))
                    open_blockchain_address_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Open", "Exploit",))
                    open_exploit_results = Cursor.fetchall()

                    Cursor.execute(PSQL_Select_Query_1, ("Closed", "Domain Spoof",))
                    closed_domain_spoof_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Closed", "Data Leakage",))
                    closed_data_leakages = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Closed", "Phishing",))
                    closed_phishing_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Closed", "Blockchain Transaction",))
                    closed_blockchain_transaction_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Closed", "Blockchain Address",))
                    closed_blockchain_address_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_1, ("Closed", "Exploit",))
                    closed_exploit_results = Cursor.fetchall()

                    Cursor.execute(PSQL_Select_Query_2, ("Domain Spoof", Mixed_Options,))
                    mixed_domain_spoof_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_2, ("Data Leakage", Mixed_Options,))
                    mixed_data_leakages = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_2, ("Phishing", Mixed_Options,))
                    mixed_phishing_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_2, ("Blockchain Transaction", Mixed_Options,))
                    mixed_blockchain_transaction_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_2, ("Blockchain Address", Mixed_Options,))
                    mixed_blockchain_address_results = Cursor.fetchall()
                    Cursor.execute(PSQL_Select_Query_2, ("Exploit", Mixed_Options,))
                    mixed_exploit_results = Cursor.fetchall()

                    Cursor.execute("""SELECT plugin, COUNT(*) AS counted FROM tasks WHERE plugin IS NOT NULL GROUP BY plugin ORDER BY counted DESC, plugin LIMIT 10;""")
                    most_common_tasks = Cursor.fetchall()
                    data = {"Open Issues": [{"Domain Spoofs": open_domain_spoof_results[0][0], "Data Leakages": open_data_leakages[0][0], "Phishing Attacks": open_phishing_results[0][0], "Blockchain Transactions": open_blockchain_transaction_results[0][0], "Blockchain Addresses": open_blockchain_address_results[0][0], "Exploits": open_exploit_results[0][0]}], "Closed Issues": [{"Domain Spoofs": closed_domain_spoof_results[0][0], "Data Leakages": closed_data_leakages[0][0], "Phishing Attacks": closed_phishing_results[0][0], "Blockchain Transactions": closed_blockchain_transaction_results[0][0], "Blockchain Addresses": closed_blockchain_address_results[0][0], "Exploits": closed_exploit_results[0][0]}], "Mixed Issues": [{"Domain Spoofs": mixed_domain_spoof_results[0][0], "Data Leakages": mixed_data_leakages[0][0], "Phishing Attacks": mixed_phishing_results[0][0], "Blockchain Transactions": mixed_blockchain_transaction_results[0][0], "Blockchain Addresses": mixed_blockchain_address_results[0][0], "Exploits": mixed_exploit_results[0][0]}], "Most Common Tasks": [{}]}
                    
                    for mc_task in most_common_tasks:
                        data["Most Common Tasks"][0][mc_task[0]] = mc_task[1]

                    return jsonify(data), 200

                else:

                    if Authentication_Verified.get("Message"):
                        return jsonify({"Error": Authentication_Verified["Message"]}), 500

                    else:
                        return jsonify({"Error": "Unauthorised."}), 500

            else:
                return jsonify({"Error": "Missing Authorization header."}), 500

        except Exception as e:
            app.logger.error(e)
            return jsonify({"Error": "Unknown error."}), 500

    @app.route('/dropsession')
    def dropsession():

        try:

            if session.get('user'):
                username = session.get('user')
                session.pop('user', None)
                session.pop('is_admin', False)
                Message = f"Session for user: {username} terminated."
                app.logger.warning(Message)
                Create_Event(Message)

            return render_template('index.html', loggedout=True)

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('index'))

    @app.route('/events', methods=['GET'])
    def events():

        try:

            if session.get('user'):
                Cursor.execute("SELECT * FROM events ORDER BY event_id DESC LIMIT 1000")
                events = Cursor.fetchall()
                return render_template('events.html', username=session.get('user'), events=events)

            else:
                session["next_page"] = "events"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('events'))

    @app.route('/api/v1/event_details', methods=['POST'])
    @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
    def api_event_details():

        try:

            if 'Authorization' in request.headers:
                Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                Authentication_Verified = API_verification(Auth_Token)

                if Authentication_Verified.get("Token"):
                    data = {}
                    Cursor.execute('SELECT * FROM events ORDER BY event_id DESC LIMIT 100')

                    for Event in Cursor.fetchall():
                        data[Event[0]] = [{"Description": Event[1], "Created Timestamp": Event[2]}]

                    return jsonify(data), 200

                else:

                    if Authentication_Verified.get("Message"):
                        return jsonify({"Error": Authentication_Verified["Message"]}), 500

                    else:
                        return jsonify({"Error": "Unauthorised."}), 500

            else:
                return jsonify({"Error": "Missing Authorization header."}), 500

        except:
            return jsonify({"Error": "Unknown Exception Occurred."}), 500

    @app.route('/tasks', methods=['GET', 'POST'])
    def tasks():

        try:

            if session.get('user'):
                session['form_step'] = 0
                session['form_type'] = ""
                session['task_frequency'] = ""
                session['task_description'] = ""
                session['task_limit'] = 0
                session['task_query'] = ""
                session['task_id'] = 0
                Cursor.execute("SELECT * FROM tasks")
                task_results = Cursor.fetchall()
                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=task_results)

            else:
                session["next_page"] = "tasks"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('tasks'))

    @app.route('/tasks/duplicate/<taskid>', methods=['POST'])
    def duplicate_task(taskid):

        try:

            if session.get('user') and session.get('is_admin'):

                def dup_task(dup_id):
                    dup_id = int(dup_id)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (dup_id,))
                    result = Cursor.fetchone()

                    if result:
                        Current_Timestamp = General.Date() # Variable set to create consistency in timestamps across two seperate database queries.
                        Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (result[1], result[2], result[3], result[4], str(result[5]), "Stopped", str(Current_Timestamp), str(Current_Timestamp)))
                        Connection.commit()

                        if result[4]:
                            time.sleep(1)
                            Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (result[1], result[2], result[3], result[4], str(result[5]), "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                            result = Cursor.fetchone()
                            task_id = result[0]

                            try:
                                my_cron = CronTab(user=getpass.getuser())
                                job = my_cron.new(command=f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(task_id)}')
                                job.setall(result[4])
                                my_cron.write()

                            except Exception as e:
                                app.logger.error(e)

                        Message = f"Task ID {str(dup_id)} duplicated by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                if "," in taskid:

                    for task in taskid.split(","):
                        dup_task(task)

                else:
                    dup_task(taskid)

                return redirect(url_for('tasks'))

            else:

                if not session.get('user'):
                    session["next_page"] = "tasks"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('tasks'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('tasks'))

    @app.route('/tasks/return/<tasktype>', methods=['POST'])
    def return_task(tasktype):

        try:

            if session.get('user') and session.get('is_admin'):

                if tasktype in ["new", "edit"]:

                    if session.get('form_step') == 1:
                        return redirect(url_for('tasks'))

                    elif session.get('form_step') == 2:
                        session['form_step'] = 1

                        if tasktype == "new":
                            return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'), is_admin=session.get('is_admin'), form_step=session.get('form_step'), new_task=True, frequency_field=session.get('task_frequency'), description_field=session.get('task_description'), task_type_field=session.get('form_type'), Valid_Plugins=Valid_Plugins)

                        elif tasktype == "edit":
                            print(session.get('task_id'))
                            Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (session.get('task_id'),))
                            result = Cursor.fetchone()
                            return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'), is_admin=session.get('is_admin'), form_step=session.get('form_step'), edit_task=True, frequency_field=session.get('task_frequency'), description_field=session.get('task_description'), task_type_field=session.get('form_type'), Valid_Plugins=Valid_Plugins, results=result)

                    else:
                        return redirect(url_for('tasks'))

                else:
                    return redirect(url_for('tasks'))

            else:

                if not session.get('user'):
                    session["next_page"] = "tasks"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('tasks'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('tasks'))

    @app.route('/tasks/delete/<taskid>', methods=['POST'])
    def delete_task(taskid):

        try:

            if session.get('user') and session.get('is_admin'):

                def del_task(del_id):
                    del_id = int(del_id)
                    Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s", (del_id,))
                    result = Cursor.fetchone()

                    if result:

                        try:
                            my_cron = CronTab(user=getpass.getuser())

                            for job in my_cron:

                                if job.command == f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(del_id)}':
                                    my_cron.remove(job)
                                    my_cron.write()

                        except:
                            Cursor.execute("SELECT * FROM tasks")
                            results = Cursor.fetchall()
                            return render_template('tasks.html', username=session.get('user'),
                                                   form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'), results=results,
                                                   error=f"Failed to remove task ID {str(del_id)} from crontab.")

                    Cursor.execute("DELETE FROM tasks WHERE task_id = %s;", (del_id,))
                    Connection.commit()
                    Message = f"Task ID {str(del_id)} deleted by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in taskid:

                    for task in taskid.split(","):
                        del_task(task)

                else:
                    del_task(taskid)

                return redirect(url_for('tasks'))

            else:

                if not session.get('user'):
                    session["next_page"] = "tasks"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('tasks'))

        except Exception as e:
            app.logger.error(e)
            Cursor.execute("SELECT * FROM tasks")
            results = Cursor.fetchall()
            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                   is_admin=session.get('is_admin'), results=results,
                                   error="Invalid value provided. Failed to delete object.")

    @app.route('/tasks/run/<taskid>', methods=['POST'])
    def run_task(taskid):

        try:

            if session.get('user') and session.get('is_admin'):
                Plugin_ID = int(taskid)
                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (Plugin_ID,))
                result = Cursor.fetchone()

                if result[6] == "Running":
                    Cursor.execute("SELECT * FROM tasks")
                    task_results = Cursor.fetchall()
                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                           is_admin=session.get('is_admin'), results=task_results,
                                           error="Task is already running.")

                if Output_API_Checker(result[2]) == "Failed":
                    Cursor.execute("SELECT * FROM tasks")
                    task_results = Cursor.fetchall()
                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                           is_admin=session.get('is_admin'), results=task_results,
                                           api_check="Failed")

                else:
                    Plugin_to_Call = plugin_caller.Plugin_Caller(Plugin_Name=result[2], Limit=result[5], Query=result[1], Task_ID=Plugin_ID)
                    plugin_caller_thread = threading.Thread(target=Plugin_to_Call.Call_Plugin)
                    plugin_caller_thread.start()
                    return redirect(url_for('tasks'))

            else:

                if not session.get('user'):
                    session["next_page"] = "tasks"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('tasks'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('tasks'))

    @app.route('/tasks/new', methods=['POST'])
    def new_task():

        try:

            if session.get('user') and session.get('is_admin'):

                if session.get('form_step') == 0:
                    session['form_step'] += 1
                    return render_template('tasks.html', username=session.get('user'),
                                           form_type=session.get('form_type'),
                                           is_admin=session.get('is_admin'), form_step=session.get('form_step'),
                                           new_task=True,
                                           Valid_Plugins=Valid_Plugins)

                elif session.get('form_step') == 1:

                    if request.form.get('tasktype') and request.form.get('tasktype') in Valid_Plugins:

                        if 'frequency' in request.form:
                            session['task_frequency'] = request.form['frequency']
                            task_frequency_regex = re.search(
                                r"[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}",
                                session.get('task_frequency'))

                            if not task_frequency_regex and not session.get('task_frequency') == "":
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       form_type=session.get('form_type'),
                                                       is_admin=session.get('is_admin'), new_task=True,
                                                       Valid_Plugins=Valid_Plugins,
                                                       error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* */5 * * *\"")

                        if 'description' in request.form:
                            session['task_description'] = html.escape(request.form['description'])

                        session['form_type'] = request.form['tasktype']
                        session['form_step'] += 1

                        if session.get('form_type') not in Plugins_without_Limit:

                            if session.get('form_type') == "PhishTank Search":
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), new_task=True,
                                                       Valid_Plugins=Valid_Plugins,
                                                       is_admin=session.get('is_admin'),
                                                       phish_sites=Phishing_Sites, use_limit=True,
                                                       api_check=Output_API_Checker(session.get('form_type')))

                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       new_task=True, is_admin=session.get('is_admin'),
                                                       form_step=session.get('form_step'), use_limit=True,
                                                       api_check=Output_API_Checker(session.get('form_type')))

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                   form_step=session.get('form_step'), new_task=True,
                                                   Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'),
                                                   api_check=Output_API_Checker(session.get('form_type')))

                    else:
                        return render_template('tasks.html', username=session.get('user'),
                                               form_type=session.get('form_type'),
                                               new_task=True, Valid_Plugins=Valid_Plugins,
                                               is_admin=session.get('is_admin'),
                                               form_step=session.get('form_step'),
                                               error="Invalid task type, please select an option from the provided list for the Task Type field.")

                elif session.get('form_step') == 2:

                    if 'query' in request.form:

                        if request.form['query']:
                            Frequency_Error = ""
                            session['task_query'] = request.form['query']

                            if request.form.get('limit'):

                                for char in session.get('task_query'):

                                    if char in Bad_Characters:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_type=session.get('form_type'),
                                                               form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'), new_task=True,
                                                               use_limit=True,
                                                               error="Invalid query specified, please provide a valid query with no special characters.")

                                try:
                                    session['task_limit'] = int(request.form['limit'])

                                except:
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_type=session.get('form_type'),
                                                           form_step=session.get('form_step'),
                                                           is_admin=session.get('is_admin'), new_task=True,
                                                           use_limit=True,
                                                           error="Invalid limit specified, please provide a valid limit represented by a number.")

                            else:

                                if session.get('form_type') not in Plugins_without_Limit:

                                    for char in session.get('task_query'):

                                        if char in Bad_Characters:
                                            return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'),
                                                                   is_admin=session.get('is_admin'), new_task=True,
                                                                   use_limit=True,
                                                                   error="Invalid query specified, please provide a valid query with no special characters.")

                                    if session.get("form_type") == "PhishTank Search":

                                        if not any(session['task_query'] in p for p in Phishing_Sites):
                                            return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'),
                                                                   is_admin=session.get('is_admin'), use_limit=True,
                                                                   phish_sites=Phishing_Sites, new_task=True,
                                                                   error="Invalid query selected, please choose a pre-defined query from the list.")

                                else:

                                    for char in session.get('task_query'):

                                        if char in Bad_Characters:
                                            return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'),
                                                                   is_admin=session.get('is_admin'), new_task=True,
                                                                   error="Invalid query specified, please provide a valid query with no special characters.")

                                    if session.get("form_type") == "PhishTank Search":

                                        if not any(session['task_query'] in p for p in Phishing_Sites):
                                            return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'),
                                                                   is_admin=session.get('is_admin'),
                                                                   phish_sites=Phishing_Sites, new_task=True,
                                                                   error="Invalid query selected, please choose a pre-defined query from the list.")

                            Current_Timestamp = General.Date()  # Variable set as it is needed for two different functions and needs to be consistent.
                            Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (
                            session.get('task_query'), session.get('form_type'), session.get('task_description'),
                            session.get('task_frequency'), session.get('task_limit'), "Stopped",
                            Current_Timestamp, Current_Timestamp,))
                            Connection.commit()
                            time.sleep(1)

                            if session.get('task_frequency'):
                                Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (
                                session.get('task_query'), session.get('form_type'), session.get('task_description'),
                                session.get('task_frequency'), str(session.get('task_limit')),
                                "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                                result = Cursor.fetchone()
                                current_task_id = result[0]

                                try:
                                    my_cron = CronTab(user=getpass.getuser())
                                    job = my_cron.new(command=f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(current_task_id)}')
                                    job.setall(session.get('task_frequency'))
                                    my_cron.write()
                                    Message = f"Task ID {(current_task_id)} created by {session.get('user')}."
                                    app.logger.warning(Message)
                                    Create_Event(Message)

                                except:
                                    Frequency_Error = f"Task created but no cronjob was created due to the supplied frequency being invalid, please double check the frequency for task ID {str(session.get('task_id'))} and use the \"Edit\" button to update it in order for the cronjob to be created."

                            session['form_step'] = 0
                            Cursor.execute("SELECT * FROM tasks")
                            results = Cursor.fetchall()

                            if Frequency_Error:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       new_task=True, is_admin=session.get('is_admin'),
                                                       results=results, error=Frequency_Error)

                            return redirect(url_for('tasks'))

                        else:

                            if session.get('form_type') not in Plugins_without_Limit:

                                if session.get('form_type') == "PhishTank Search":
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_step=session.get('form_step'), new_task=True,
                                                           is_admin=session.get('is_admin'), phish_sites=Phishing_Sites,
                                                           error="Empty query, please provide a valid term to search for.")

                                else:
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_type=session.get('form_type'),
                                                           new_task=True, is_admin=session.get('is_admin'),
                                                           form_step=session.get('form_step'), use_limit=True,
                                                           error="Empty query, please provide a valid term to search for.")

                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       new_task=True, is_admin=session.get('is_admin'),
                                                       form_step=session.get('form_step'),
                                                       error="Empty query, please provide a valid term to search for.")

                    else:

                        if session.get('form_type') not in Plugins_without_Limit:

                            if session.get('form_type') == "PhishTank Search":
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), new_task=True,
                                                       is_admin=session.get('is_admin'), phish_sites=Phishing_Sites,
                                                       error="Empty query, please provide a valid term to search for.")

                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       new_task=True, is_admin=session.get('is_admin'),
                                                       form_step=session.get('form_step'), use_limit=True,
                                                       error="Empty query, please provide a valid term to search for.")

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                   form_type=session.get('form_type'),
                                                   new_task=True, is_admin=session.get('is_admin'),
                                                   form_step=session.get('form_step'),
                                                   error="Empty query, please provide a valid term to search for.")

                else:
                    return redirect(url_for('tasks'))

            else:

                if not session.get('user'):
                    session["next_page"] = "tasks"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('tasks'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('tasks'))

    @app.route('/tasks/edit/<taskid>', methods=['POST'])
    def edit_task(taskid):

        try:

            if session.get('user') and session.get('is_admin'):

                if session.get('form_step') == 0:

                    session['task_id'] = int(taskid)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                    results = Cursor.fetchone()

                    if results:
                        session['form_step'] += 1
                        print(results)
                        return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results)

                    else:
                        Cursor.execute("SELECT * FROM tasks;", (session.get('task_id'),))
                        results = Cursor.fetchall()
                        return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, results=results, is_admin=session.get('is_admin'), error="Invalid value provided. Failed to edit object.")

                elif session.get('form_step') == 1:
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                    results = Cursor.fetchone()

                    if request.form.get('tasktype') and request.form.get('tasktype') in Valid_Plugins:

                        if 'frequency' in request.form:
                            session['task_frequency'] = request.form['frequency']
                            task_frequency_regex = re.search(r"[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+", session.get('task_frequency'))

                            if not task_frequency_regex and not session.get('task_frequency') == "":
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, results=results, is_admin=session.get('is_admin'), error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* /5 * * *\"")

                        if 'description' in request.form:
                            session['task_description'] = html.escape(request.form['description'])

                        session['form_type'] = request.form['tasktype']
                        session['form_step'] += 1

                        if session.get('form_type') not in Plugins_without_Limit:

                            if session.get('form_type') == "PhishTank Search":
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, use_limit=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results, phish_sites=Phishing_Sites, api_check=Output_API_Checker(session.get('form_type')))

                            else:
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), use_limit=True, edit_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results, api_check=Output_API_Checker(session.get('form_type')))

                        else:
                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results, api_check=Output_API_Checker(session.get('form_type')))

                    else:
                        return render_template('tasks.html', username=session.get('user'),
                                               form_step=session.get('form_step'),
                                               edit_task=True, Valid_Plugins=Valid_Plugins,
                                               is_admin=session.get('is_admin'), results=results,
                                               error="Invalid task type, please select an option from the provided list for the Task Type field.")

                elif session.get('form_step') == 2:
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                    results = Cursor.fetchone()

                    if 'query' in request.form:

                        if request.form['query']:
                            Frequency_Error = ""
                            session['task_query'] = request.form['query']

                            if request.form.get('limit'):

                                for char in session.get('task_query'):

                                    if char in Bad_Characters:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_step=session.get('form_step'), use_limit=True,
                                                               edit_task=True, Valid_Plugins=Valid_Plugins,
                                                               results=results, is_admin=session.get('is_admin'),
                                                               form_type=session.get('form_type'),
                                                               error="Invalid query specified, please provide a valid query with no special characters.")

                                if session.get("form_type") == "PhishTank Search":

                                    if not any(session['task_query'] in p for p in Phishing_Sites):
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_type=session.get('form_type'),
                                                               form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'),
                                                               phish_sites=Phishing_Sites, edit_task=True,
                                                               error="Invalid query selected, please choose a pre-defined query from the list.")

                                try:
                                    session['task_limit'] = int(request.form['limit'])

                                except:
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_step=session.get('form_step'),
                                                           use_limit=True, edit_task=True,
                                                           form_type=session.get('form_type'),
                                                           Valid_Plugins=Valid_Plugins, results=results,
                                                           is_admin=session.get('is_admin'),
                                                           error="Invalid limit specified, please provide a valid limit represented by a number.")

                            else:

                                for char in session.get('task_query'):

                                    if char in Bad_Characters:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_type=session.get('form_type'),
                                                               form_step=session.get('form_step'), edit_task=True,
                                                               is_admin=session.get('is_admin'),
                                                               Valid_Plugins=Valid_Plugins, results=results,
                                                               error="Invalid query specified, please provide a valid query with no special characters.")

                                if session.get("form_type") == "PhishTank Search":

                                    if not any(session['task_query'] in p for p in Phishing_Sites):
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_type=session.get('form_type'),
                                                               form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'),
                                                               phish_sites=Phishing_Sites, edit_task=True,
                                                               error="Invalid limit selected, please choose a pre-defined query from the list.")

                            Update_Cron = False

                            if session.get('task_frequency') != "":
                                Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                                result = Cursor.fetchone()
                                original_frequency = result[0]

                                if not original_frequency == session.get('task_frequency'):
                                    Update_Cron = True

                            else:

                                if results[4] != "":

                                    try:
                                        my_cron = CronTab(user=getpass.getuser())

                                        for job in my_cron:

                                            if job.command == f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(session.get("task_id"))}':
                                                my_cron.remove(job)
                                                my_cron.write()

                                    except:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_type=session.get('form_type'),
                                                               form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'),
                                                               phish_sites=Phishing_Sites, edit_task=True,
                                                               error="Failed to update cron job.")

                            Cursor.execute('UPDATE tasks SET query = %s, plugin = %s, description = %s, frequency = %s, task_limit = %s, updated_at = %s WHERE task_id = %s', (
                            session.get('task_query'), session.get('form_type'), session.get('task_description'),
                            session.get('task_frequency'), session.get('task_limit'), General.Date(),
                            session.get('task_id'),))
                            Connection.commit()
                            time.sleep(1)

                            if Update_Cron:
                                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                                result = Cursor.fetchone()
                                current_task_id = result[0]

                                try:
                                    my_cron = CronTab(user=getpass.getuser())

                                    for job in my_cron:

                                        if job.command == f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(current_task_id)}':
                                            my_cron.remove(job)
                                            my_cron.write()

                                    job = my_cron.new(command=f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(current_task_id)}')
                                    job.setall(session.get('task_frequency'))
                                    my_cron.write()

                                except:
                                    Frequency_Error = f"Task updated but no cronjob was added, and any valid original cron jobs for this task have been removed due to an invalid frequency being supplied, please double check the frequency for task ID {str(session.get('task_id'))} and use the \"Edit\" button to edit the frequency to create a cronjob."

                            Message = f"Task ID {str(session.get('task_id'))} updated by {session.get('user')}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            session['form_step'] = 0
                            Cursor.execute("SELECT * FROM tasks")
                            results = Cursor.fetchall()

                            if Frequency_Error:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       new_task=True, is_admin=session.get('is_admin'),
                                                       results=results, error=Frequency_Error)

                            return redirect(url_for('tasks'))

                        else:

                            if session.get('form_type') not in Plugins_without_Limit:

                                if session.get('form_type') == "PhishTank Search":
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_type=session.get('form_type'),
                                                           new_task=True, is_admin=session.get('is_admin'),
                                                           results=results, phish_sites=Phishing_Sites,
                                                           form_step=session.get('form_step'), use_limit=True,
                                                           error="Empty query, please provide a valid term to search for.")

                                else:
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_type=session.get('form_type'),
                                                           new_task=True, is_admin=session.get('is_admin'),
                                                           results=results,
                                                           form_step=session.get('form_step'), use_limit=True,
                                                           error="Empty query, please provide a valid term to search for.")

                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), new_task=True,
                                                       Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'),
                                                       results=results,
                                                       error="Empty query, please provide a valid term to search for.")

                    else:

                        if session.get('form_type') not in Plugins_without_Limit:

                            if session.get('form_type') == "PhishTank Search":
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       new_task=True, is_admin=session.get('is_admin'), results=results,
                                                       phish_sites=Phishing_Sites,
                                                       form_step=session.get('form_step'), use_limit=True,
                                                       error="Empty query, please provide a valid term to search for.")

                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       new_task=True, is_admin=session.get('is_admin'), results=results,
                                                       form_step=session.get('form_step'), use_limit=True,
                                                       error="Empty query, please provide a valid term to search for.")

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                   form_step=session.get('form_step'), new_task=True,
                                                   Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'),
                                                   results=results,
                                                   error="Empty query, please provide a valid term to search for.")

                else:
                    return redirect(url_for('tasks'))

            else:

                if not session.get('user'):
                    session["next_page"] = "tasks"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('tasks'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('tasks'))

    @app.route('/api/v1/task_details', methods=['POST'])
    @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
    def api_task_details():

        try:

            if 'Authorization' in request.headers:
                Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                Authentication_Verified = API_verification(Auth_Token)

                if Authentication_Verified.get("Token"):
                    data = {}
                    Cursor.execute('SELECT * FROM tasks ORDER BY task_id DESC LIMIT 1000')

                    for Task in Cursor.fetchall():
                        data[Task[0]] = [{"Query": Task[1], "Plugin": Task[2], "Description": Task[3], "Frequency": Task[4], "Limit": Task[5], "Status": Task[6], "Created Timestamp": Task[7], "Last Updated Timestamp": Task[8]}]

                    return jsonify(data), 200

                else:

                    if Authentication_Verified.get("Message"):
                        return jsonify({"Error": Authentication_Verified["Message"]}), 500

                    else:
                        return jsonify({"Error": "Unauthorised."}), 500

            else:
                return jsonify({"Error": "Missing Authorization header."}), 500

        except Exception as e:
            app.logger.error(e)
            return jsonify({"Error": "Unknown Exception Occurred."}), 500

    @app.route('/results/new', methods=['POST'])
    def new_result():

        try:

            if session.get('user') and session.get('is_admin'):

                if session.get('form_step') == 0:
                    session['form_step'] += 1
                    return render_template('results.html', username=session.get('user'),
                                           form_step=session.get('form_step'),
                                           is_admin=session.get('is_admin'))

                elif session.get('form_step') == 1:
                    name = request.form['name']
                    URL = request.form['url']
                    Type = request.form['type']

                    if name and URL and Type:

                        for char in Bad_Characters:

                            if char in name:
                                return render_template('results.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'),
                                                       error="Bad characters identified in the name field, please remove special characters from the name field.")

                        if not Type in Finding_Types:
                            return render_template('results.html', username=session.get('user'),
                                                   form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'),
                                                   error="Result type is not valid.")

                        Query_List = General.Convert_to_List(name)
                        Hosts_List = General.Convert_to_List(URL)
                        Iterator_List = []
                        i = 0

                        while i < len(Hosts_List) and len(Query_List):
                            URL_Regex = re.search(
                                r"https?:\/\/(www\.)?([a-z\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?)",
                                Hosts_List[i])

                            if URL_Regex:
                                Iterator_List.append(i)
                                i += 1

                            else:
                                return render_template('results.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'),
                                                       error="Invalid URL(s).")

                        for Iterator in Iterator_List:
                            URL_Regex = re.search(
                                r"https?:\/\/(www\.)?([a-z\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?)",
                                Hosts_List[Iterator])

                            try:
                                Cursor.execute('INSERT INTO results (task_id, title, status, plugin, domain, link, created_at, updated_at, result_type) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)', (
                                0, str(Query_List[Iterator]), "Open", "Manual Entry", str(URL_Regex.group(2)),
                                str(Hosts_List[Iterator]), General.Date(), General.Date(), Type,))
                                Connection.commit()

                            except Exception as e:
                                app.logger.error(e)

                        return redirect(url_for('results'))

                    else:
                        return render_template('results.html', username=session.get('user'),
                                               form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'),
                                               error="Invalid entry / entries, please fill out all necessary fields.")

                else:
                    return redirect(url_for('results'))

            else:

                if not session.get('user'):
                    session["next_page"] = "results"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('results'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('results'))

    @app.route('/results/delete/<resultid>', methods=['POST'])
    def delete_result(resultid):

        try:

            if session.get('user') and session.get('is_admin'):

                def del_result(resultid):
                    result_id = int(resultid)
                    Cursor.execute("SELECT * FROM results WHERE result_id = %s", (result_id,))
                    Result = Cursor.fetchone()

                    if Result[9]:
                        Screenshot_File = f"{File_Path}/static/protected/screenshots/{Result[9]}"

                        if os.path.exists(Screenshot_File):
                            os.remove(Screenshot_File)

                    if Result[10]:
                        Output_File = f"{File_Path}/{Result[10]}"

                        if os.path.exists(Output_File):
                            os.remove(Output_File)

                    Cursor.execute("DELETE FROM results WHERE result_id = %s;", (result_id,))
                    Connection.commit()
                    Message = f"Result ID {str(result_id)} deleted by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in resultid:

                    for resid in resultid.split(","):
                        del_result(resid)

                else:
                    del_result(resultid)

                return redirect(url_for('results'))

            else:

                if not session.get('user'):
                    session["next_page"] = "results"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('results'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('results'))


    @app.route('/results/changestatus/<status>/<resultid>', methods=['POST'])
    def change_result_status(status, resultid):

        try:

            if session.get('user') and session.get('is_admin'):

                if status in ["open", "close", "inspect", "review"]:
                    resultid = int(resultid)

                    if status == "open":
                        Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Open", str(General.Date()), resultid,))
                        Message = f"Result ID {str(resultid)} closed by {session.get('user')}."

                    elif status == "close":
                        Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Closed", str(General.Date()), resultid,))
                        Message = f"Result ID {str(resultid)} re-opened by {session.get('user')}."

                    elif status == "inspect":
                        Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Inspecting", str(General.Date()), resultid,))
                        Message = f"Result ID {str(resultid)} now under inspection by {session.get('user')}."

                    elif status == "review":
                        Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Reviewing", str(General.Date()), resultid,))
                        Message = f"Result ID {str(resultid)} now under review by {session.get('user')}."

                    Connection.commit()
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return redirect(url_for('results'))

                else:
                    return redirect(url_for('results'))

            else:

                if not session.get('user'):
                    session["next_page"] = "results"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('results'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('results'))

    @app.route('/results/details/<resultid>', methods=['POST', 'GET'])
    def result_details(resultid):

        try:

            if session.get('user'):
                resultid = int(resultid)
                Chrome_Config = Connectors.Load_Chrome_Configuration()

                if all(os.path.exists(Config) for Config in Chrome_Config):
                    Screenshot_Permitted = True

                else:
                    Screenshot_Permitted = False

                Cursor.execute("SELECT * FROM results WHERE result_id = %s", (resultid,))
                Result_Table_Results = Cursor.fetchone()
                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (Result_Table_Results[1],))
                Task_Table_Results = Cursor.fetchone()
                return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'), details=True, is_admin=session.get('is_admin'), results=Result_Table_Results, task_results=Task_Table_Results, Screenshot_Permitted=Screenshot_Permitted)

            else:
                session["next_page"] = "results"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('results'))

    @app.route('/results', methods=['GET'])
    def results():

        try:

            if session.get('user'):
                session['form_step'] = 0
                Cursor.execute("SELECT * FROM results ORDER BY result_id DESC LIMIT 1000")
                return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall())

            else:
                session["next_page"] = "results"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('results'))

    @app.route('/api/v1/result_details', methods=['POST'])
    @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
    def api_result_details():

        try:

            if 'Authorization' in request.headers:
                Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                Authentication_Verified = API_verification(Auth_Token)

                if Authentication_Verified.get("Token"):
                    data = {}
                    Cursor.execute('SELECT * FROM results ORDER BY result_id DESC LIMIT 1000')

                    for Result in Cursor.fetchall():
                        data[Result[0]] = [{"Associated Task ID": Result[1], "Title": Result[2], "Plugin": Result[3], "Status": Result[4], "Domain": Result[5], "Link": Result[6], "Created Timestamp": Result[7], "Last Updated Timestamp": Result[8], "Screenshot Location": Result[9], "Output File Location": Result[10], "Result Type": Result[11], "Screenshot Requested": Result[12]}]

                    return jsonify(data), 200

                else:

                    if Authentication_Verified.get("Message"):
                        return jsonify({"Error": Authentication_Verified["Message"]}), 500

                    else:
                        return jsonify({"Error": "Unauthorised."}), 500

            else:
                return jsonify({"Error": "Missing Authorization header."}), 500

        except:
            return jsonify({"Error": "Unknown Exception Occurred."}), 500

    def check_security_requirements(Password):

        try:

            if not len(Password) >= 8:
                return False

            else:
                Lower = any(Letter.islower() for Letter in Password)
                Upper = any(Letter.isupper() for Letter in Password)
                Digit = any(Letter.isdigit() for Letter in Password)

                if not Upper or not Lower or not Digit:
                    return False

                else:
                    Special_Character_Regex = re.search('[\@\_\-\!\#\$\%\^\&\*\(\)\~\`\<\>\]\[\}\{\|\:\;\'\"\/\?\.\,\+\=]+', Password)

                    if not Special_Character_Regex:
                        return False

                    else:
                        return True

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('dashboard'))

    @app.route('/account/new', methods=['POST'])
    def new_account():

        try:

            if session.get('user') and session.get('is_admin'):

                if session.get('form_step') == 0:
                    session['form_step'] += 1
                    session['form_type'] = "CreateUser"
                    return render_template('account.html', username=session.get('user'),
                                           form_type=session.get('form_type'), form_step=session.get('form_step'),
                                           is_admin=session.get('is_admin'), api_key=session.get('api_key'),
                                           current_user_id=session.get('user_id'))

                elif session.get('form_step') == 1:

                    if not request.form['Username']:
                        return render_template('account.html', username=session.get('user'),
                                               form_type=session.get('form_type'), form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                               error="Please provide a valid username.", api_key=session.get('api_key'),
                                               current_user_id=session.get('user_id'))

                    for char in Bad_Characters:

                        if char in request.form['Username']:
                            return render_template('account.html', username=session.get('user'),
                                                   form_type=session.get('form_type'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(),
                                                   error="Bad character detected in username.",
                                                   api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                    Cursor.execute('SELECT * FROM users WHERE username = %s', (request.form.get('Username'),))
                    User = Cursor.fetchone()

                    if User:
                        Cursor.execute('SELECT * FROM users')
                        return render_template('account.html', username=session.get('user'),
                                               form_type=session.get('form_type'), form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                               error="Username already exists.", api_key=session.get('api_key'),
                                               current_user_id=session.get('user_id'))

                    Cursor.execute('SELECT * FROM users')

                    if request.form['New_Password'] != request.form['New_Password_Retype']:
                        return render_template('account.html', username=session.get('user'),
                                               form_type=session.get('form_type'), form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                               error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                               api_key=session.get('api_key'), current_user_id=session.get('user_id'))

                    else:
                        Password_Security_Requirements_Check = check_security_requirements(
                            request.form['New_Password'])

                        if Password_Security_Requirements_Check == False:
                            return render_template('account.html', username=session.get('user'),
                                                   form_type=session.get('form_type'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(), requirement_error=[
                                    "The supplied password does not meet security requirements. Please make sure the following is met:",
                                    "- The password is longer that 8 characters.",
                                    "- The password contains 1 or more UPPERCASE and 1 or more lowercase character.",
                                    "- The password contains 1 or more number.",
                                    "- The password contains one or more special character. Ex. @."],
                                                   api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                        else:

                            if 'is_new_user_admin' in request.form:
                                New_User_Is_Admin = "True"

                            else:
                                New_User_Is_Admin = "False"

                            password = generate_password_hash(request.form['New_Password'])
                            Cursor.execute(
                                'INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)',
                                (request.form['Username'], password, "False", New_User_Is_Admin,))
                            Connection.commit()

                            if New_User_Is_Admin == "True":
                                Message = f"New administrative user created by {session.get('user')}."

                            else:
                                Message = f"New low-privileged user created by {session.get('user')}."

                            return render_template('account.html', username=session.get('user'),
                                                   form_type=session.get('form_type'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(), message=Message,
                                                   api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))
                            Create_Event(Message)

                else:
                    return redirect(url_for('account'))

            else:

                if not session.get('user'):
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('account'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account/password/change/<account>', methods=['POST'])
    def change_account_password(account):

        try:

            if session.get('user'):

                if str(account) == "mine" and 'Current_Password' in request.form and 'New_Password' in request.form and 'New_Password_Retype' in request.form:
                    Current_Password = request.form['Current_Password']
                    Cursor.execute('SELECT * FROM users WHERE username = %s', (session.get('user'),))
                    User = Cursor.fetchone()
                    Current_Password_Check = check_password_hash(User[2], Current_Password)

                    if not Current_Password_Check:
                        return render_template('account.html', username=session.get('user'),
                                               form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                               error="Current Password is incorrect.", api_key=session.get('api_key'),
                                               current_user_id=account)

                    else:

                        if request.form['New_Password'] != request.form['New_Password_Retype']:
                            return render_template('account.html', username=session.get('user'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                                   api_key=session.get('api_key'),
                                                   current_user_id=account)

                        else:
                            Password_Security_Requirements_Check = check_security_requirements(request.form['New_Password'])

                            if not Password_Security_Requirements_Check:
                                return render_template('account.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), requirement_error=[
                                        "The supplied password does not meet security requirements. Please make sure the following is met:",
                                        "- The password is longer that 8 characters.",
                                        "- The password contains 1 or more UPPERCASE and 1 or more lowercase character.",
                                        "- The password contains 1 or more number.",
                                        "- The password contains one or more special character. Ex. @."],
                                                       api_key=session.get('api_key'),
                                                       current_user_id=account)

                            else:
                                password = generate_password_hash(request.form['New_Password'])
                                Cursor.execute('UPDATE users SET password = %s WHERE user_id = %s', (password, User[0],))
                                Connection.commit()
                                return render_template('account.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), message="Password changed.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=account)

                else:

                    if session.get('is_admin'):

                        if session.get('form_step') == 0:
                            session['other_user_id'] = int(account)
                            session['form_step'] += 1
                            session['form_type'] = "ChangePassword"
                            return render_template('account.html', username=session.get('user'),
                                                   form_type=session.get('form_type'),
                                                   form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'), api_key=session.get('api_key'),
                                                   current_user_id=session.get('other_user_id'))

                        elif session.get('form_step') == 1:
                            Cursor.execute('SELECT * FROM users WHERE user_id = %s', (session.get('other_user_id'),))
                            User = Cursor.fetchone()

                            if request.form['New_Password'] != request.form['New_Password_Retype']:
                                return render_template('account.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'),
                                                       error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=session.get('other_user_id'))

                            else:
                                Password_Security_Requirements_Check = check_security_requirements(request.form['New_Password'])

                                if not Password_Security_Requirements_Check:
                                    return render_template('account.html', username=session.get('user'),
                                                           form_type=session.get('form_type'),
                                                           form_step=session.get('form_step'),
                                                           is_admin=session.get('is_admin'), requirement_error=[
                                            "The supplied password does not meet security requirements. Please make sure the following is met:",
                                            "- The password is longer that 8 characters.",
                                            "- The password contains 1 or more UPPERCASE and 1 or more lowercase character.",
                                            "- The password contains 1 or more number.",
                                            "- The password contains one or more special character. Ex. @."],
                                                           api_key=session.get('api_key'),
                                                           current_user_id=session.get('other_user_id'))

                                else:
                                    password = generate_password_hash(request.form['New_Password'])
                                    Cursor.execute('UPDATE users SET password = %s WHERE user_id = %s', (password, User[0],))
                                    Connection.commit()
                                    return redirect(url_for('account'))

                        else:
                            return redirect(url_for('account'))

                    else:
                        return redirect(url_for('account'))

            else:
                session["next_page"] = "account"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account/apikey/get', methods=['POST'])
    def get_account_apikey():

        try:

            if session.get('user'):

                def Create_Session_Based_JWT(ID, Username):
                    Expiry_Hours = API_Validity_Limit / 60
                    Expiry = datetime.utcnow() + timedelta(hours=Expiry_Hours)
                    payload = {"id": ID, "name": Username, "iat": datetime.utcnow(), "exp": Expiry, "nonce": secrets.token_hex(32)}
                    JWT = jwt.encode(payload, API_Secret, algorithm='HS256')
                    return JWT.decode('utf-8')

                user_id = int(session.get('user_id'))

                if user_id == session.get('user_id'):
                    Cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
                    User_Info = Cursor.fetchone()

                    if User_Info[5] and User_Info[6]:

                        try:
                            Decoded_Token = jwt.decode(User_Info[5], API_Secret, algorithm='HS256')
                            Cursor.execute('SELECT * FROM users ORDER BY user_id')
                            return render_template('account.html', username=session.get('user'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(), message="Current token is still valid.",
                                                   api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                        except:
                            API_Key = Create_Session_Based_JWT(User_Info[0], User_Info[1])
                            Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, General.Date(), User_Info[0],))
                            Connection.commit()
                            Message = f"New API Key generated for user ID {str(user_id)} by {session.get('user')}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            session['api_key'] = API_Key
                            Cursor.execute('SELECT * FROM users ORDER BY user_id')
                            return render_template('account.html', username=session.get('user'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(),
                                                   message="New API Key generated successfully.",
                                                   api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                    else:
                        API_Key = Create_Session_Based_JWT(User_Info[0], User_Info[1])
                        Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, General.Date(), User_Info[0],))
                        Connection.commit()
                        Message = f"New API Key generated for user ID {str(user_id)} by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        session['api_key'] = API_Key
                        Cursor.execute('SELECT * FROM users ORDER BY user_id')
                        return render_template('account.html', username=session.get('user'),
                                               form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                               results=Cursor.fetchall(), message="New API Key generated successfully.",
                                               api_key=session.get('api_key'), current_user_id=session.get('user_id'))

                else:
                    Cursor.execute('SELECT * FROM users ORDER BY user_id')
                    return render_template('account.html', username=session.get('user'),
                                           form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                           results=Cursor.fetchall(),
                                           message="You are only able to generate API's for your own user.",
                                           api_key=session.get('api_key'), current_user_id=session.get('user_id'))

            else:
                session["next_page"] = "account"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account/delete/<accountid>', methods=['POST'])
    def delete_account(accountid):

        try:

            if session.get('user') and session.get('is_admin'):

                def del_account(accountid):
                    user_id = int(accountid)
                    Cursor.execute("DELETE FROM users WHERE user_id = %s;", (user_id,))
                    Connection.commit()
                    Message = f"User ID {str(user_id)} deleted by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in accountid:

                    for userid in accountid.split(","):
                        del_account(userid)

                else:
                    del_account(accountid)

                return redirect(url_for('account'))

            else:

                if not session.get('user'):
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('account'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account/disable/<accountid>', methods=['POST'])
    def disable_account(accountid):

        try:

            if session.get('user') and session.get('is_admin'):

                def dis_account(accountid):
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("True", user_id,))
                    Connection.commit()
                    Message = f"User ID {str(user_id)} blocked by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in accountid:

                    for userid in accountid.split(","):
                        dis_account(userid)

                else:
                    dis_account(accountid)

                return redirect(url_for('account'))

            else:

                if not session.get('user'):
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('account'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account/enable/<accountid>', methods=['POST'])
    def enable_account(accountid):

        try:

            if session.get('user') and session.get('is_admin'):

                def enble_account(accountid):
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("False", user_id,))
                    Connection.commit()
                    Message = f"User ID {str(user_id)} unblocked by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in accountid:

                    for userid in accountid.split(","):
                        enble_account(userid)

                else:
                    enble_account(accountid)

                return redirect(url_for('account'))

            else:

                if not session.get('user'):
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('account'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account/demote/<accountid>', methods=['POST'])
    def demote_account(accountid):

        try:

            if session.get('user') and session.get('is_admin'):

                def dem_account(accountid):
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("False", user_id,))
                    Connection.commit()
                    Message = f"Privileges for user ID {str(user_id)} demoted by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in accountid:

                    for userid in accountid.split(","):
                        dem_account(userid)

                else:
                    dem_account(accountid)

                return redirect(url_for('account'))

            else:

                if not session.get('user'):
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('account'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account/promote/<accountid>', methods=['POST'])
    def promote_account(accountid):

        try:

            if session.get('user') and session.get('is_admin'):

                def pro_account(accountid):
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("True", user_id,))
                    Connection.commit()
                    Message = f"Privileges for user ID {str(user_id)} promoted by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in accountid:

                    for userid in accountid.split(","):
                        pro_account(userid)

                else:
                    pro_account(accountid)

                return redirect(url_for('account'))

            else:

                if not session.get('user'):
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

                else:
                    return redirect(url_for('account'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/account', methods=['GET'])
    def account():

        try:

            if session.get('user'):

                if session.get('is_admin'):
                    session['form_step'] = 0
                    session['form_type'] = ""
                    session['other_user_id'] = 0
                    Cursor.execute('SELECT * FROM users ORDER BY user_id')
                    return render_template('account.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), api_key=session.get('api_key'), current_user_id=session.get('user_id'))

                else:
                    return render_template('account.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), api_key=session.get('api_key'), current_user_id=session.get('user_id'))

            else:
                session["next_page"] = "account"
                return redirect(url_for('no_session'))

        except Exception as e:
            app.logger.error(e)
            return redirect(url_for('account'))

    @app.route('/api/v1/account_details', methods=['POST'])
    @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
    def api_account_details():

        try:

            if 'Authorization' in request.headers:
                Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                Authentication_Verified = API_verification(Auth_Token)

                if Authentication_Verified.get("Token"):

                    if Authentication_Verified["Admin"]:
                        data = {}
                        Cursor.execute('SELECT * FROM users ORDER BY user_id DESC LIMIT 1000')

                        for User in Cursor.fetchall():
                            data[User[0]] = [{"Username": User[1], "Blocked": User[3], "Admin": User[4]}]

                        return jsonify(data), 200

                    else:
                        return jsonify({"Error": "Insufficient privileges."}), 500

                else:

                    if Authentication_Verified.get("Message"):
                        return jsonify({"Error": Authentication_Verified["Message"]}), 500

                    else:
                        return jsonify({"Error": "Unauthorised."}), 500

            else:
                return jsonify({"Error": "Missing Authorization header."}), 500

        except Exception as e:
            app.logger.error(e)

    app.run(debug=Application_Details[0], host=Application_Details[1], port=Application_Details[2], threaded=True, ssl_context=context)