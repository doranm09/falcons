from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.xml import pretty_print

GVM_HOST = 'openvas'  # Docker network name or IP
GVM_PORT = 9390
GVM_USER = 'admin'
GVM_PASS = 'your_password'

def openvas_session():
    # open the TLS socket…
    conn = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)
    # wrap it in a Gmp instance
    gmp = Gmp(conn)
    # log in
    gmp.login(GVM_USER, GVM_PASS)
    return gmp

def create_target(gmp, cidr):
    response = gmp.create_target(name=f"Target {cidr}", hosts=cidr)
    return response.xpath("create_target_response/@id")[0]

def start_scan(gmp, target_id):
    # NVT Full and Fast Scan ID (default config)
    config_id = "daba56c8-73ec-11df-a475-002264764cea"
    task = gmp.create_task(name=f"Scan {target_id}", config_id=config_id, target_id=target_id)
    task_id = task.xpath("create_task_response/@id")[0]
    gmp.start_task(task_id)
    return task_id

def get_report_id(gmp, task_id):
    task = gmp.get_task(task_id)
    return task.xpath("//task/last_report/report/@id")[0]

def download_report(gmp, report_id):
    return gmp.get_report(report_id=report_id, report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5')  # XML