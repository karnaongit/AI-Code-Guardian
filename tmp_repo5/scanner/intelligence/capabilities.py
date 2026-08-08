# scanner/intelligence/capabilities.py

# A mapping of known library functions and patterns to abstract behaviors (capabilities).
# This allows the rules engine to check for "execute_sql_query" rather than needing to know
# every single framework's exact SQL execution method.

CAPABILITIES = {
    # ----------------------------------------
    # SQL INJECTION (execute_sql_query)
    # ----------------------------------------
    "sqlite3.Cursor.execute": "execute_sql_query",
    "sqlite3.execute": "execute_sql_query",
    "django.db.models.query.raw": "execute_sql_query",
    "django.db.connection.cursor.execute": "execute_sql_query",
    "flask_sqlalchemy.SQLAlchemy.engine.execute": "execute_sql_query",
    "psycopg2.cursor.execute": "execute_sql_query",
    "mysql.connector.cursor.execute": "execute_sql_query",
    "sqlalchemy.text": "execute_sql_query",
    "cursor.execute": "execute_sql_query",
    "db.execute": "execute_sql_query",
    "execute": "execute_sql_query",
    "executescript": "execute_sql_query",
    "execute_many": "execute_sql_query",
    
    # ----------------------------------------
    # COMMAND INJECTION (execute_os_command)
    # ----------------------------------------
    "os.system": "execute_os_command",
    "os.popen": "execute_os_command",
    "subprocess.Popen": "execute_os_command",
    "subprocess.call": "execute_os_command",
    "subprocess.run": "execute_os_command",
    "subprocess.check_output": "execute_os_command",
    "commands.getoutput": "execute_os_command",
    "commands.getstatusoutput": "execute_os_command",
    "pty.spawn": "execute_os_command",
    "system": "execute_os_command",
    "popen": "execute_os_command",

    # ----------------------------------------
    # UNSAFE EVALUATION (unsafe_evaluation)
    # ----------------------------------------
    "eval": "unsafe_evaluation",
    "exec": "unsafe_evaluation",
    "yaml.load": "unsafe_evaluation",
    "yaml.unsafe_load": "unsafe_evaluation",
    "pickle.loads": "unsafe_evaluation",
    "pickle.load": "unsafe_evaluation",
    "ast.literal_eval": "unsafe_evaluation", # Although literal_eval is safer, often misused

    # ----------------------------------------
    # PATH TRAVERSAL (read_file / write_file)
    # ----------------------------------------
    "open": "read_file",
    "os.open": "read_file",
    "io.open": "read_file",
    "codecs.open": "read_file",
    "file": "read_file",
    "read": "read_file",
    "write": "write_file",

    # ----------------------------------------
    # SSRF & XXE (make_http_request / parse_xml)
    # ----------------------------------------
    "requests.get": "make_http_request",
    "requests.post": "make_http_request",
    "requests.request": "make_http_request",
    "urllib.request.urlopen": "make_http_request",
    "urllib2.urlopen": "make_http_request",
    "httplib.HTTPConnection": "make_http_request",
    "xml.etree.ElementTree.parse": "parse_xml",
    "xml.etree.ElementTree.fromstring": "parse_xml",
    "lxml.etree.parse": "parse_xml",
    "lxml.etree.fromstring": "parse_xml",

    # ----------------------------------------
    # HTTP INPUTS (Sources of Taint)
    # ----------------------------------------
    "flask.request.args.get": "read_http_input",
    "flask.request.form.get": "read_http_input",
    "flask.request.json": "read_http_input",
    "flask.request.values.get": "read_http_input",
    "django.http.HttpRequest.GET.get": "read_http_input",
    "django.http.HttpRequest.POST.get": "read_http_input",
    "django.http.HttpRequest.body": "read_http_input",

    # ----------------------------------------
    # HTTP RESPONSES (Sinks for XSS)
    # ----------------------------------------
    "flask.render_template_string": "write_http_response",
    "django.http.HttpResponse": "write_http_response",
    "django.shortcuts.render": "write_http_response",
}
