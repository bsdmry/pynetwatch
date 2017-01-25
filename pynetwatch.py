#!/usr/bin/env python
# Copyright (c) 2016, Igor Volodin 
# All rights reserved. 
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met: 
#
# * Redistributions of source code must retain the above copyright notice, 
#   this list of conditions and the following disclaimer. 
# * Redistributions in binary form must reproduce the above copyright 
#   notice, this list of conditions and the following disclaimer in the 
#   documentation and/or other materials provided with the distribution. 
# * Neither the name of  nor the names of its contributors may be used to 
#   endorse or promote products derived from this software without specific 
#   prior written permission. 
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE

from lxml import etree
from pprint import pprint
import subprocess
import os
import shlex
import socket
from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import threading
import time
import pexpect
snmpchecks = [] #id, [iparray] community, oid, isCheck?, expval, current, status
pingchecks = [] # id, ip, isCheck?, current, status
tcpconnchecks = []
rcmdchecks = []#id, ip, port, username, passwd, promt, cmd,  isCheck?, expval, current, status
STATUS_OK = 1
STATUS_NOK = 0
STATUS_UNKNOW = 2
htmlpage = ''

page_style = ''' 
   figure {
    background: #5f6a72;
    padding: 10px; 
    width: 250px; 
    float: left; 
    margin: 0 10px 10px 0; 
    text-align: center; 
    border-radius: 20px 20px 20px 20px;
    -moz-border-radius: 20px 20px 20px 20px;
   }
   article {
   padding: 5px;
   }
   figcaption {
    color: #fff; 
   }
   DIV.area{
    padding: 10px;
    border-radius: 5px 5px 5px 5px;
    -moz-border-radius: 5px 5px 5px 5px;
    overflow:hidden;
    background: #D1ECFF

   }
   DIV.area-info{
    padding: 10px;
    border-radius: 10px 10px 10px 10px;
    -moz-border-radius: 10px 10px 10px 10px;
    background: #82B1FF
   }
   DIV.device-row{
   display: flex;
   align-items: flex-start;
   justify-content: center;
   }
   .tableDev{
	display: table;
	width: 100%;
	
   }
   .tableDevBody {
	display: table-row-group;
   }
   .tableDevRow {
	display: table-row;
   }
   .tableDevCellDescr {
	border: 1px solid #999999;
	display: table-cell;
	padding: 3px 10px;
	background: #fff;
   }	
   .tableDevCellStatOk {
	border: 1px solid #999999;
	display: table-cell;
	padding: 3px 10px;
	background: #00FF21;
        font-size: 70%;
   }	
   .tableDevCellStatNok {
	border: 1px solid #999999;
	display: table-cell;
	padding: 3px 10px;
	background: #FF0000;
        font-size: 70%;
   }	
   .tableDevCellStatUnknow {
	border: 1px solid #999999;
	display: table-cell;
	padding: 3px 10px;
	background: #808080;
   }	
   .tableDevCellInfo {
	border: 1px solid #999999;
	display: table-cell;
	padding: 3px 10px;
	background: #7FFFFF;
        font-size: 70%;
   }
	'''

def snmpget(targetIP, community, oid):
        result = None
	good_ip = None
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	for ip in targetIP:
	    #print "Test IP " + ip
	    check = s.connect_ex((ip, 162))
	    if check == 0:
		#print "It's good ip " + ip
	        good_ip = ip
		break
	if good_ip == None:
	    return None
        args = shlex.split("snmpget -v 2c -c " + community + " " + good_ip + " " + oid)
        child = subprocess.Popen(args,stdout = subprocess.PIPE, stderr= subprocess.PIPE)
	output,error = child.communicate()
	rcode = child.returncode
	if rcode != 0:
		return None
        for line in output.split('\n'):
                if len(line) == 0:
                        continue
                resp = line.split(' ')
                result = ' '.join(resp[3:])
		break
        return result

def remotecmd(ip, port, login, pwd, promt, cmd):
	result = None
	ssh = pexpect.spawn('ssh '+login+'@'+str(ip)+' -p ' + port + ' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q')	
	ssh.expect('assword:')
        ssh.sendline(pwd)
	ssh.expect(promt)
        ssh.sendline(cmd)
	ssh.expect(promt)
	result = ssh.before
	ssh.close()
	return result.splitlines()[1]

def ping(targetIP):
	response = os.system("ping -c 1 " + targetIP + ' > /dev/null')
	if (response == 0):
		return True
	else:
		return False

def tcpconnect(targetIP, port):
	s = socket.socket()
	iport = int(port)
	result = s.connect_ex((targetIP, iport))
	if (result == 0):
		return True
	else:
		return False

def add_check(record, verify):
    chk_id = record.get('id')
    chk_type = record.get('type')
    if chk_type == 'snmpget':
    	ip = []
    	community = ''
    	oid = ''
   	expected = ''
	current = ''
	for el in node.getiterator('ip'):
	    ip.append(el.text)
	for el in node.getiterator('community'):
	    community = el.text
	    break
	for el in node.getiterator('oid'):
	    oid = el.text
	    break
	if verify:
	    for el in node.getiterator('expected'):
		expected = el.text
		break
	snmpchecks.append([chk_id, ip, community, oid, verify, expected, current, STATUS_UNKNOW])
    elif chk_type == 'remotecmd':
        ip = ''
	port = ''
	username = ''
	passwd = ''
	promt = ''
	cmd = ''
	expected = ''
	current = ''
	for el in node.getiterator('ip'):
	    ip = el.text
	    break
	for el in node.getiterator('port'):
	    port = el.text
	    break
	for el in node.getiterator('username'):
	    username = el.text
	    break
	for el in node.getiterator('password'):
	    passwd = el.text
	    break
	for el in node.getiterator('promt'):
	    promt = el.text
	    break
	for el in node.getiterator('cmd'):
	    cmd = el.text
	    break
	if verify:
	    for el in node.getiterator('expected'):
		expected = el.text
		break
	rcmdchecks.append([chk_id, ip, port, username, passwd, promt, cmd, verify,  expected, current, STATUS_UNKNOW])

    elif chk_type == 'ping':
	ip =''
	current = ''
	for el in node.getiterator('ip'):
	    ip = el.text
	    break
	pingchecks.append([chk_id, ip, verify, current, STATUS_UNKNOW])
    elif chk_type == 'tcpconnect':
	ip =''
	port = ''
	current = ''
	for el in node.getiterator('ip'):
	    ip = el.text
	    break
	for el in node.getiterator('port'):
	    port = el.text
	    break
	tcpconnchecks.append([chk_id, ip, port, verify, current, STATUS_UNKNOW])
	
def poll_devices():
	i = 0
	chk_num = len(snmpchecks)
	while i < chk_num:
		value = snmpget(snmpchecks[i][1], snmpchecks[i][2], snmpchecks[i][3])
		snmpchecks[i][6] = value
		if snmpchecks[i][4]:
			if value == snmpchecks[i][5]:
				snmpchecks[i][5] = STATUS_OK
			else:
				snmpchecks[i][5] = STATUS_NOK
		i = i + 1
	i = 0
	chk_num = len(rcmdchecks)
	while i < chk_num:
		value = remotecmd(rcmdchecks[i][1], rcmdchecks[i][2], rcmdchecks[i][3], rcmdchecks[i][4], rcmdchecks[i][5], rcmdchecks[i][6])
		rcmdchecks[i][9] = value
		if rcmdchecks[i][7]:
			if value == rcmdchecks[i][8]:
				rcmdchecks[i][10] = STATUS_OK
			else:
				rcmdchecks[i][10] = STATUS_NOK
		i = i + 1
	i = 0
	chk_num = len(pingchecks)
	while i < chk_num:
		value = ping(pingchecks[i][1])
		pingchecks[i][3] = value
		if value:
			pingchecks[i][4] = STATUS_OK
		else:
			pingchecks[i][4] = STATUS_NOK
		i = i + 1
	i = 0
	chk_num = len(tcpconnchecks)
	while i < chk_num:
		value = tcpconnect(tcpconnchecks[i][1], tcpconnchecks[i][2])
		tcpconnchecks[i][4] = value
		if value:
			tcpconnchecks[i][5] = STATUS_OK
		else:
			tcpconnchecks[i][5] = STATUS_NOK
		i = i + 1
def html_target_row_status(chk_id, chk_type, row_type, row_description):
    status_descr = {0:'Not OK', 1:'OK', 2:'Unknow'}
    html = ''
    record_class = ''
    value  = ''
    status = ''

    if chk_type == 'snmpget':
	for snmprec in snmpchecks:
	    if snmprec[0] == chk_id:
                value = snmprec[6]
	        status =  snmprec[7]
		break
    if chk_type == 'remotecmd':
	for rcmdrec in rcmdchecks:
	    if rcmdrec[0] == chk_id:
                value = rcmdrec[9]
	        status = rcmdrec[10]
		break
    if chk_type == 'ping':
	for pingrec in pingchecks:
	    if pingrec[0] == chk_id:
                value = status_descr[pingrec[4]]
	        status = pingrec[4]
		break
    if chk_type == 'tcpconnect':
	for tcpconnrec in tcpconnchecks:
	    if tcpconnrec[0] == chk_id:
                value = status_descr[tcpconnrec[5]]
	        status =  tcpconnrec[5]
    		break
    if row_type == 'info':
	record_class = 'tableDevCellInfo'
    else:
        if status == STATUS_OK:
            record_class = 'tableDevCellStatOk'
        elif status == STATUS_NOK:
            record_class = 'tableDevCellStatNok'
        else:
            record_class = 'tableDevCellStatUnknow'

    html = """<div class="tableDevRow">
		<div class="tableDevCellDescr">%s</div>
		<div class="%s">%s</div>
	     </div>""" % (row_description, record_class, value)
    return html

def html_target_card(name, rows):
    html = '''<figure>
	<p>%s</p>
	<figcaption>Text1</figcaption>
	<div class="tableDev">
	<div class="tableDevBody">
	%s
	</div> 
	</div> 
	</figure>''' % (name, rows)
    return html
def html_target_block(device_line):
    html = '''<div class="device-row">
	%s
	</div>''' % device_line
    return html
def html_area_block(name, device_lines):
    html = '''<div class="area">
	<div class="area-info">
	%s
	</div>
	<article>
	%s
	</article>
	</div><p>&nbsp</p>''' % (name, device_lines) 
    return html

def html_all_page(title, styles, body):
    html = '''<!DOCTYPE html>
	<html>
	<head>
	<meta charset="utf-8">
	<meta http-equiv="refresh" content="45" />
	<title>%s</title>
	<style>
	%s
	</style>
	</head>
	<body>
	%s
	</body>
	</html>
	''' % (title, styles, body)
    return html

def gen_page(xml):
    root = xml.getroot()
    areas = xml.xpath('//lab/area')
    areas_block = ''
    for area in areas:
	#print area.xpath('./name/text()')[0]
	targets = area.xpath("./target")
	target_lines = [targets[i:i + 4] for i in xrange(0, len(targets), 4)] # 4 device cards per line
	targets_block = ''
	for target_line in target_lines:
	    html_cards = ''
	    for target in target_line:
	        cards = target.xpath("./*[re:test(local-name(), 'check|info')]",namespaces={'re': "http://exslt.org/regular-expressions"})
                html_card_rows = ''
	        for card in cards:
		    html_card_rows = html_card_rows + html_target_row_status(card.get('id'), card.get('type'), card.tag, card.xpath("./name/text()")[0])
	        html_cards = html_cards + html_target_card(target.xpath('./name/text()')[0],  html_card_rows)
            targets_block = targets_block + html_target_block(html_cards)
	areas_block = areas_block + html_area_block(area.xpath('./name/text()')[0], targets_block)
    return html_all_page('Test lab', page_style, areas_block)

class CustomHandler(SimpleHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
	s.send_header("Content-type", "text/html")
	s.end_headers()
    def do_GET(s):
	s.send_response(200)
	s.send_header("Content-type", "text/html")
	s.end_headers()
	s.wfile.write(htmlpage)
#-------------------------------------------------------------	
print "Load XML configuration"
tree = etree.parse('cfg.xml')
print "Build checks&info table"
for node in tree.iterfind('.//check'): #
    add_check(node, True)
for node in tree.iterfind('.//info'): #
    add_check(node, False)
#------------------
print "Set default initial statuses"
htmlpage = gen_page(tree)
print "Init HTTP server"
server = HTTPServer(('', 8080), CustomHandler)
thread = threading.Thread(target = server.serve_forever)
thread.daemon = True

try:
    print "Start HTTP server"
    thread.start()
except KeyboardInterrupt:
    server.shutdown()
    sys.exit(0)

while(True):
    time.sleep(60)
    print 'Re-poll devices'
    poll_devices()
    print "Re-poll finished. Generate new table"
    htmlpage = gen_page(tree)
