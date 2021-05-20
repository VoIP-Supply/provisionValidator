from scapy.all import ARP, Ether, srp
from urllib.request import urlopen
import manuf
import time
import socket, re


def scanIP(target_ip, browser):
    # IP Address for the destination
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    p = manuf.MacParser(update=True) # load the manufacturer db

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        vendor = p.get_manuf(received.hwsrc)
        clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'vendor': vendor})

    # print clients
    print("Available devices in the network:")
    print("        IP" + " "*18+"MAC" + " "*12+"VENDOR")
    i = 1
    for client in clients:
        if int(client['ip'].split('.')[-1]) < 10:
            continue
        if (client['vendor'] == 'Cisco'):
            print("{:<5}{:20}{:16}{}".format(str(i) + ')',client['ip'], client['mac'].replace(':', ''), client['vendor']))
            Pd1 = get_cisco_url(browser, client['ip'], 'admin', 'admin')
            print('    IP: ' + Pd1.ip + ' MAC: ' + Pd1.mac + ' DHCP: ' + Pd1.static + ' URL: ' + Pd1.web + ' ' + Pd1.url + ' Model: ' + Pd1.model + ' Firmware: ' + Pd1.version + ' Status: ' + Pd1.status)
        elif (client['vendor'] == 'Polycom'):
            print("{:<5}{:20}{:16}{}".format(str(i) + ')',client['ip'], client['mac'].replace(':', ''), client['vendor']))
            Pd1 = get_polycom_url(browser, client['ip'], '456')
            print('    IP: ' + Pd1.ip + ' MAC: ' + Pd1.mac + ' DHCP: ' + Pd1.static + ' URL: ' + Pd1.web + ' ' + Pd1.url + ' Model: ' + Pd1.model + ' Firmware: ' + Pd1.version + ' Status: ' + Pd1.status)
        elif (client['vendor'] == 'Grandstr'):
            print("{:<5}{:20}{:16}{}".format(str(i) + ')',client['ip'], client['mac'].replace(':', ''), client['vendor']))
            Pd1 = get_grandstream_url(browser, client['ip'], 'admin', 'admin')
            print('    IP: ' + Pd1.ip + ' MAC: ' + Pd1.mac + ' DHCP: ' + Pd1.static + ' URL: ' + Pd1.web + ' ' + Pd1.url + ' Model: ' + Pd1.model + ' Firmware: ' + Pd1.version + ' Status: ' + Pd1.status)
        elif (client['vendor'] == 'ObihaiTe'):
            print("{:<5}{:20}{:16}{}".format(str(i) + ')',client['ip'], client['mac'].replace(':', ''), client['vendor']))
            Pd1 = get_obihai_url(browser, client['ip'], 'admin', 'admin')
            print('    IP: ' + Pd1.ip + ' MAC: ' + Pd1.mac + ' DHCP: ' + Pd1.static + ' URL: ' + Pd1.web + ' ' + Pd1.url + ' Model: ' + Pd1.model + ' Firmware: ' + Pd1.version + ' Status: ' + Pd1.status)
        elif (client['vendor'] == 'YealinkX'):
            print("{:<5}{:20}{:16}{}".format(str(i) + ')',client['ip'], client['mac'].replace(':', ''), client['vendor']))
            Pd1 = get_yealink_url(browser, client['ip'], 'admin', 'admin')
            print('    IP: ' + Pd1.ip + ' MAC: ' + Pd1.mac + ' DHCP: ' + Pd1.static + ' URL: ' + Pd1.web + ' ' + Pd1.url + ' Model: ' + Pd1.model + ' Firmware: ' + Pd1.version + ' Status: ' + Pd1.status)
        elif (client['vendor'] == 'Panasoni'):
            print("{:<5}{:20}{:16}{}".format(str(i) + ')', client['ip'], client['mac'].replace(':', ''),client['vendor']))
            Pd1 = get_panasonic_url(browser, client['ip'], 'admin', 'adminpass')
            print('    IP: ' + Pd1.ip + ' MAC: ' + Pd1.mac + ' DHCP: ' + Pd1.static + ' URL: ' + Pd1.web + ' ' + Pd1.url + ' Model: ' + Pd1.model + ' Firmware: ' + Pd1.version + ' Status: ' + Pd1.status)
        elif (client['vendor'] == 'JetwayIn'):
            continue
        else:
            print("{:<5}{:20}{:16}{}".format(str(i) + ')',client['ip'], client['mac'].replace(':', ''), client['vendor']))

        i = i + 1
        get_prov_file(client['mac'].replace(':', ''))

class PhoneData:
    def __init__(self, ip, mac, web, url, static, model, version, status):
        self.ip = ip
        self.mac = mac
        self.web = web
        self.url = url
        self.static = static
        self.model = model
        self.version = version
        self.status = status


def get_prov_file(mac):
    url = 'https://prov.voipfulfillment.com/' + mac + '.cfg'
    if 'phone' in mac:
        url = 'https://prov.voipfulfillment.com/Broadvoice/Polycom/vvx/' + mac + '.cfg'
    #print(url)
    try:
      with urlopen(url) as response:
        obiConfigURL = False
        provURL = ''
        for line in response:
          line = line.decode('utf-8').strip()  # Decoding the binary data to text.
          #print(line)
          if 'CONFIG_FILES' in line: # Polycom default
            get_prov_file(mac + '-phone') # try again
          elif 'auto_provision.server.url' in line:  # look for Yealink url
            print("    VF URL: Yealink: " + line[32:].strip() + "\n" )
            provURL = line[32:].strip()
            break
          elif '<P237>' in line:  # look for Grandstream url
            match = re.search('>([^<>]*)<', line) # regex to return the text between two tags
            print("    VF URL: Grandstream: " + match.group(1) + "\n")
            provURL = match.group(1)
            break
          elif '<Profile_Rule>' in line:  # look for Cisco url
            match = re.search('>([^<>]*)<', line) # regex to return the text between two tags
            print("    VF URL: Cisco: " + match.group(1) + "\n")
            provURL = match.group(1)
            break
          elif '<Profile_Rule_B' in line:  # look for Cisco arena1
            match = re.search('>([^<>]*)<', line) # regex to return the text between two tags
            print("    VF URL: Cisco: " + match.group(1) + "\n" )
            provURL = match.group(1)
            break
          elif 'prov.server.static' in line:  # look for Algo url
            print("    VF URL: Algo: " + line[21:].strip() + "\n")
            provURL = line[21:].strip()
            break
          elif 'CFG_STANDARD_FILE_PATH="' in line and '#CFG_' not in line:  # look for Panasonic url
            provURL = line[24:].strip()
            if provURL == '"':
                provURL = 'standard url is empty'
                print("    VF URL: Panasonic: " + provURL + "\n")
                continue
            print("    VF URL: Panasonic: " + provURL + "\n")
            break
          elif 'CFG_PRODUCT_FILE_PATH="' in line and '#CFG_' not in line:  # look for Panasonic url
            provURL = line[23:].strip()
            if provURL == '"':
                provURL = 'product url is empty'
                continue
            print("    VF URL: Panasonic: " + provURL + "\n")
            break
          elif 'device.prov.serverName' in line:  # Polycom url
            #print(line)
            match = (re.search('device.prov.serverName',line))
            #print ('end: ' + str(match.end()))
            start = int(match.end() + 2)
            end = line.find('\"',start)
            #print('quote: ' + str(end))
            print("    VF URL: Poly: " +line[start:end] + "\n")
            provURL = line[start:end]
            break
          elif line == '<V>':
              obiConfigURL = True
              continue
          elif obiConfigURL == True:
              print("    VF URL: Obihai: " + line + "\n")
              provURL = line.strip()
              break
          elif 'MAC' in line and 'not found.' in line:
              print('    VF URL: ' + line)
              break

    except Exception as e:
        status = str(e.msg)
        print("    VF URL: not found")

    return provURL


def get_polycom_url(browser,ip,passwordText):
    try:
        Pd1 = PhoneData(ip,"","","","","","","OK")

        browser.get('https://' + ip + '/login.htm')
        time.sleep(0.5)
        password = browser.find_element_by_name("password")
        password.send_keys(passwordText)
        browser.find_element_by_name("login").submit()
        time.sleep(0.5)
        Pd1.model = browser.title  #'Polycom - Trio 8800 Configuration Utility'
        value = Pd1.model.find('IP')
        if Pd1.model.find('IP') > 0:
            type = "IP"
            sleepTime = 1
        elif Pd1.model.find('VVX') > 0:
            type = "VVX"
            sleepTime = 0.5
        elif Pd1.model.find('Trio') > 0:
            type = "Trio"
            sleepTime = 0.5
        else:
            type = "NO"
            sleepTime = 1
            #id="notemsg"  Invalid password. Try again.
            if browser.find_element_by_id("notemsg").text.find('Invalid password') > -1:
                Pd1.status = 'login failed'
                return Pd1

        browser.get('https://' + ip + '/home.htm')
        time.sleep(sleepTime)
        if type == "VVX":
            Pd1.model = browser.find_element_by_id("phoneModelInformationTd").text
            Pd1.version = browser.find_element_by_id("UCS_software_version").text
            Pd1.mac = browser.find_element_by_xpath("/html/body/div[@id='wrapper']/div[@id='content']/div[@id='pageContent']/div[@id='home']/table/tbody/tr[4]/td[2]").text.replace(':','')
        elif type == "Trio":
            Pd1.model = browser.find_element_by_id("phoneModelInformationTd").text
            Pd1.version = browser.find_element_by_id("UCS_software_version").text
            Pd1.mac = browser.find_element_by_xpath("/html/body/div[@id='wrapper']/div[@id='content']/div[@id='pageContent']/div[@id='home']/div[1]/table/tbody/tr[4]/td[2]").text.replace(':','')

        else: # IP Soundpoint
            Pd1.version = browser.find_element_by_xpath("/html/body/div[@id='wrapper']/div[@id='content']/div[@id='pageContent']/div[@id='home']/table/tbody/tr[6]/td[2]").text
            Pd1.model = browser.find_element_by_xpath("/html/body/div[@id='wrapper']/div[@id='content']/div[@id='pageContent']/div[@id='home']/table/tbody/tr[2]/td[2]").text
            Pd1.mac = browser.find_element_by_xpath("/html/body/div[@id='wrapper']/div[@id='content']/div[@id='pageContent']/div[@id='home']/table/tbody/tr[4]/td[2]").text.replace(':','')

        browser.get('https://' + ip + '/provConf.htm')
        time.sleep(sleepTime)
        Pd1.web = Select(browser.find_element_by_xpath("//select[@paramname='device.prov.serverType']")).first_selected_option.get_attribute("text")
        Pd1.static = Select(browser.find_element_by_xpath("//select[@paramname='device.dhcp.bootSrvUseOpt']")).first_selected_option.get_attribute("text")
        Pd1.url = browser.find_element_by_xpath("//input[@paramname='device.prov.serverName']").get_attribute("value")
        if Pd1.url == '':
            Pd1.url = 'url is empty'


    except Exception as e:
        Pd1.status = str(e.msg)
        if Pd1.status.find('TIMED_OUT') > -1 or Pd1.status.find('timeout') > -1:
            Pd1.status = 'timed out'
        elif browser.page_source == '<html><head></head><body></body></html>':
            Pd1.status = 'login failed'

    return Pd1


def get_cisco_url(browser,ip,usernameText,passwordText):
    try:
        Pd1 = PhoneData(ip,"","","","","","","OK")

        browser.get('http://' + ip)
        time.sleep(0.5)
        username = browser.find_element_by_name("user")
        username.send_keys(usernameText)
        password = browser.find_element_by_name("pwd")
        password.send_keys(passwordText)
        browser.find_element_by_xpath("//input[@value='Log In']").submit()

        time.sleep(1)
        Pd1.model = browser.title  #'Polycom - Trio 8800 Configuration Utility'
        #form autocomplete="off" id="frm" name="voice" method="post" action="apply.cgi;session_id=69f4722f54d49ee15ce05aba16ec54fc">

        session_id_start = browser.page_source.find("session_id=") + 11
        session_id_end = session_id_start + browser.page_source[session_id_start:].find('">')
        session_id = browser.page_source[session_id_start:session_id_end]

        browser.get('http://' + ip + '/Status_Router.asp;session_id=' + session_id)
        time.sleep(0.5)
        Pd1.version = browser.find_element_by_xpath("/html/body/form[@id='frm']/div[@id='bg']/table[@class='MAINTABLE']/tbody/tr[3]/td[@class='FUNTD']/table/tbody/tr/td[@class='CONTENTAREA']/div[@id='content']/table[@class='CONTENT_TABLE']/tbody/tr[2]/td[@class='NOSPACE']/table[@class='CONTENT_GROUP']/tbody/tr[@class='TABLECONTENT_D'][2]/td[@class='TABLECONTENT_TD'][2]").text
        Pd1.model = browser.find_element_by_xpath("/html/body/form[@id='frm']/div[@id='bg']/table[@class='MAINTABLE']/tbody/tr[3]/td[@class='FUNTD']/table/tbody/tr/td[@class='CONTENTAREA']/div[@id='content']/table[@class='CONTENT_TABLE']/tbody/tr[2]/td[@class='NOSPACE']/table[@class='CONTENT_GROUP']/tbody/tr[@class='TABLECONTENT_S'][1]/td[@class='TABLECONTENT_TD'][2]").text
        Pd1.mac = browser.find_element_by_xpath("/html/body/form[@id='frm']/div[@id='bg']/table[@class='MAINTABLE']/tbody/tr[3]/td[@class='FUNTD']/table/tbody/tr/td[@class='CONTENTAREA']/div[@id='content']/table[@class='CONTENT_TABLE']/tbody/tr[2]/td[@class='NOSPACE']/table[@class='CONTENT_GROUP']/tbody/tr[@class='TABLECONTENT_D'][3]/td[@class='TABLECONTENT_TD'][2]").text.replace(':', '')

        browser.get('http://' + ip + '/admin/voice/#')
        time.sleep(0.5)
        Pd1.url = browser.find_element_by_name("26799").get_attribute("value")
        if Pd1.url == '':
            Pd1.url = 'url is empty'

    except Exception as e:
        Pd1.status = str(e.msg)
        if Pd1.status.find('TIMED_OUT') > -1 or Pd1.status.find('timeout') > -1:
            Pd1.status = 'timed out'
        elif browser.page_source == '<html><head></head><body></body></html>':
            Pd1.status = 'login failed'

    return Pd1


def get_yealink_url(browser,ip,usernameText,passwordText):
    try:
        Pd1 = PhoneData(ip,"","","","","","","OK")

        browser.get('http://' + ip)
        time.sleep(0.5)
        username = browser.find_element_by_id("idUsername")
        username.send_keys(usernameText)
        password = browser.find_element_by_id("idPassword")
        password.send_keys(passwordText)
        browser.find_element_by_id("idConfirm").click()

        time.sleep(0.5)
        Pd1.model = browser.title  #'Polycom - Trio 8800 Configuration Utility'
        Pd1.version = browser.find_element_by_id("PhoneFirmware").text
        Pd1.mac = browser.find_element_by_id("tdMACAddress").text.replace(':', '')

        browser.get('http://' + ip + '/servlet?m=mod_data&p=settings-autop&q=load')
        time.sleep(0.5)

        Pd1.url = browser.find_element_by_name("AutoProvisionServerURL").get_attribute("value")
        if Pd1.url == '':
            Pd1.url = 'url is empty'

        if browser.find_element_by_id("AutoPEnableDHCPOptionOn").is_selected() == True:
            Pd1.static = 'opt66'
        else:
            Pd1.static = 'static'

    except Exception as e:
        Pd1.status = str(e.msg)
        if Pd1.status.find('TIMED_OUT') > -1 or Pd1.status.find('timeout') > -1:
            Pd1.status = 'timed out'
        elif browser.page_source.find("Incorrect username or password!") > -1 :
            Pd1.status = 'login failed'


    return Pd1

def get_panasonic_url(browser,ip,usernameText,passwordText):
    try:
        Pd1 = PhoneData(ip,"","","","","","","OK")
        time.sleep(0.5)
        browser.get('http://' + usernameText + ':' + passwordText + '@' + ip)
        time.sleep(1.0)
        if browser.page_source == '<html><head></head><body></body></html>':  # not logged in
            browser.get('http://' + usernameText + ':' + passwordText + '@' + ip)  # try again.
            time.sleep(1.0)
        Pd1.model = browser.title
        session_id_start = browser.page_source.find("LoginId=") + 8 #LoginId=22941&amp;
        session_id_end = session_id_start + browser.page_source[session_id_start:].find('&amp;')
        session_id = browser.page_source[session_id_start:session_id_end]

        browser.switch_to.frame('contents')

        time.sleep(0.5)
        bank1 = browser.find_element_by_xpath("/html/body/div[@id='disp']/table[@class='W_560 BORDER_NONE'][1]/tbody/tr[4]/td[@class='W_280 PADDING_03 BCOLOR_C9D0DA']").text
        bank2 = browser.find_element_by_xpath("/html/body/div[@id='disp']/table[@class='W_560 BORDER_NONE'][1]/tbody/tr[5]/td[@class='W_280 PADDING_03 BCOLOR_C9D0DA']").text
        Pd1.version = bank1 + ', ' + bank2

        browser.switch_to.default_content()
        browser.switch_to.frame('menu')
        time.sleep(0.5)
        browser.get('http://' + ip + '/CgiStart.cgi?LoginId=' + session_id + '&Page=status_net&no_tab=1&no_menu=1')
        time.sleep(0.5)
        Pd1.mac = browser.find_element_by_xpath("/html/body/div[@id='disp']/form/table[@class='W_560 BORDER_NONE'][1]/tbody/tr[1]/td[@class='W_300 PADDING_03 BCOLOR_C9D0DA']").text

        browser.get('http://' + ip + '/CgiStart.cgi?LoginId=' + session_id + '&Page=mainte_prov&no_tab=6&no_menu=1')
        time.sleep(0.5)
        # start with tr1, Standard File URL
        Pd1.url = browser.find_element_by_xpath("/html/body/div[@id='disp']/form/table[@class='W_560 BORDER_NONE']/tbody/tr[1]/td[@class='W_300 PADDING_03 BCOLOR_C9D0DA']/input").get_attribute("value")

        if Pd1.url == '':  # try tr2, Product File URL
            Pd1.url = browser.find_element_by_xpath("/html/body/div[@id='disp']/form/table[@class='W_560 BORDER_NONE']/tbody/tr[2]/td[@class='W_300 PADDING_03 BCOLOR_C9D0DA']/input").get_attribute("value")
            if Pd1.url == '':
                Pd1.url = 'url is empty'

    except Exception as e:
        Pd1.status = str(e.msg)
        if Pd1.status.find('TIMED_OUT') > -1 or Pd1.status.find('timeout') > -1:
            Pd1.status = 'timed out'
        elif browser.page_source.find("Incorrect username or password!") > -1:
            Pd1.status = 'login failed'
        elif Pd1.status.find('unknown error: net::ERR_CONNECTION_REFUSED') > -1:
            Pd1.status = 'web gui is off'

    return Pd1


def get_grandstream_url(browser,ip,usernameText,passwordText):
    try:
        Pd1 = PhoneData(ip,"","","","","","","OK")

        browser.get('http://' + ip) # + '/cgi-bin/login'
        time.sleep(1)
        if browser.title.find("UCM") > -1 or browser.title.find("GVC") > -1 or browser.title.find("GXV3610") > -1:
            Pd1.model = browser.title
            Pd1.status = 'skip'
        elif browser.title[:3] == 'GXV':
            type = 'GXV'
            username = browser.find_element_by_id("username")
            username.send_keys(usernameText)
            password = browser.find_element_by_id("password")
            password.send_keys(passwordText)
            time.sleep(0.25)
            browser.find_element_by_id("loginbtn").click()
            time.sleep(0.5)
            Pd1.model = browser.title

            if browser.page_source.find('Auth Failed') > -1:
                Pd1.status = 'login failure'
                return Pd1

            browser.get('http://' + ip + "/status/sysinfo.html")
            time.sleep(0.5)
            Pd1.mac = browser.find_element_by_id("pn").text.replace(':','').strip()
            Pd1.version = browser.find_element_by_id("progver").text.strip()
            Pd1.model = browser.find_element_by_id("promodel").text.strip()

            browser.get('http://' + ip + '/maintenance/upgrade.html')
            time.sleep(1)
            Pd1.url = browser.find_element_by_id("confpath").text.strip()
            Pd1.web = browser.find_element_by_class_name("selectedTxt").text.strip()
            if browser.find_element_by_id("dhcp66").is_selected():
                Pd1.static = 'Opt66'
            else:
                Pd1.static = 'Static'


        else: #HT801
            type = 'HT801'
            password = browser.find_element_by_name("P2")
            password.send_keys(passwordText)
            browser.find_element_by_name('Login').submit()
            time.sleep(0.5)
            Pd1.model = browser.title

            if browser.page_source.find('Your Login Password is not recognized') > -1:
                Pd1.status = 'login failure'
                return Pd1

            Pd1.version = browser.find_element_by_xpath("/html/body/table/tbody/tr/td/table/tbody/tr[3]/td/table/tbody/tr[6]/td[2]").text.strip()[:20]
            Pd1.model = browser.find_element_by_xpath("/html/body/table/tbody/tr/td/table/tbody/tr[3]/td/table/tbody/tr[4]/td[2]").text.strip()
            Pd1.mac = browser.find_element_by_xpath("/html/body/table/tbody/tr/td/table/tbody/tr[3]/td/table/tbody/tr[1]/td[2]").text.replace(':','').strip()

            browser.get('http://' + ip + '/cgi-bin/config')
            time.sleep(0.5)
            Pd1.url = browser.find_element_by_name("P237").get_attribute("value").strip()
            if Pd1.url == '':
                Pd1.url = 'url is empty'
            httptype = browser.find_elements_by_name("P212")
            for x in httptype:
                if x.is_selected():
                    httptypeselected = int(x.get_attribute("value"))
                    httptypes = ['TFTP', 'HTTP', 'HTTPS', 'FTP', 'FTPS']
                    httpname = httptypes[httptypeselected]
                    break

            opt66 = browser.find_elements_by_name("P145")  # .is_selected() #.first_checked_option.get_attribute("text")
            for x in opt66:
                if x.is_selected():
                    opt66selected = int(x.get_attribute("value"))
                    opt66s = ['Static', 'Opt66']
                    Pd1.static = opt66s[opt66selected]
                    break


    except Exception as e:
        Pd1.status = str(e.msg)
        if Pd1.status.find('TIMED_OUT') > -1 or Pd1.status.find('timeout') > -1:
            Pd1.status = 'timed out'
        elif browser.page_source == '<html><head></head><body></body></html>':
            Pd1.status = 'login failed'

    return Pd1


def get_obihai_url(browser,ip,usernameText,passwordText):
    try:
        Pd1 = PhoneData(ip,"","","","","","","OK")

        browser.get('http://' + usernameText + ':' + passwordText + '@' + ip)
        time.sleep(0.5)
        Pd1.model = browser.title
        browser.get('http://' + ip )
        time.sleep(0.5)
        browser.switch_to.frame('main_frame')
        Pd1.mac = browser.find_element_by_xpath("/html/body/div[@class='content']/form[1]/table[@class='xsltable'][2]/tbody[2]/tr[2]/td[@class='Tbl1_td2'][2]").text.replace(':', '').strip()
        Pd1.version = browser.find_element_by_xpath("/html/body/div[@class='content']/form[1]/table[@class='xsltable'][2]/tbody[2]/tr[6]/td[@class='Tbl1_td2'][2]").text.strip()
        Pd1.model = browser.find_element_by_xpath("/html/body/div[@class='content']/form[1]/table[@class='xsltable'][2]/tbody[2]/tr[1]/td[@class='Tbl1_td'][2]").text.strip()


        if browser.title.find('OBi302') > -1:
            provURL = get_prov_file(Pd1.mac)
            if provURL != '':
                Pd1Set = set_obihai_url(browser, ip, 'admin', 'admin', provURL)

        #browser.switch_to.frame('bot_frame')
        #browser.find_element_by_xpath("/html/body/div[@id='container']/ul[@id='nav2'][2]/li[@class='collapsed'][3]/span[@class='menuheading']").click()
        #time.sleep(0.5)
        #browser.find_element_by_xpath("/html/body/div[@id='container']/ul[@id='nav2'][2]/li[@class='expanded']/ul/li[1]/a").click()

        browser.get('http://' + ip + '/DM_S_.xml')
        time.sleep(0.5)

        Pd1.url = browser.find_element_by_name("7f7d0175").get_attribute("value").strip()
        Pd1.static = Select(browser.find_element_by_name('79d6d10d')).first_selected_option.get_attribute("text")


    except Exception as e:
        Pd1.status = str(e.msg)
        if Pd1.status.find('TIMED_OUT') > -1 or Pd1.status.find('timeout') > -1:
            Pd1.status = 'timed out'
        elif browser.page_source == '<html><head></head><body></body></html>':
            Pd1.status = 'login failed'

    return Pd1


def set_obihai_url(browser,ip,usernameText,passwordText,provURL):
    try:
        Pd1 = PhoneData(ip,"","","","","","","OK")

        browser.get('http://' + usernameText + ':' + passwordText + '@' + ip)
        time.sleep(0.5)
        Pd1.model = browser.title
        browser.switch_to.frame('bot_frame')
        browser.find_element_by_xpath("/html/body/div[@id='container']/ul[@id='nav2'][2]/li[@class='collapsed'][3]/span[@class='menuheading']").click()
        time.sleep(0.5)
        browser.find_element_by_xpath("/html/body/div[@id='container']/ul[@id='nav2'][2]/li[@class='expanded']/ul/li[1]/a").click()

        browser.get('http://' + ip + '/DM_S_.xml')
        time.sleep(0.5)

        #ConfigURL
        isChecked = browser.find_element_by_name('7f7d0175usedefault').get_attribute('checked')
        if isChecked == 'true':
            browser.find_element_by_name('7f7d0175usedefault').click()  # uncheck "Default" for ConfigURL
        time.sleep(0.25)
        newURL = browser.find_element_by_name("7f7d0175")  #ITSP ConfigURL
        newURL.clear()
        newURL.send_keys(provURL)
        isChecked = browser.find_element_by_name('79d6d10dusedefault').get_attribute('checked')
        if isChecked == 'true':
            browser.find_element_by_name('79d6d10dusedefault').click()  # uncheck "Default" for Method
        select = Select(browser.find_element_by_name('79d6d10d'))
        select.select_by_visible_text('System Start')

        #FirmwareURL
        isChecked = browser.find_element_by_name('e64ca815usedefault').get_attribute('checked')
        if isChecked == 'true':
            browser.find_element_by_name('e64ca815usedefault').click()  # uncheck "Default" for FirmwareURL
        time.sleep(0.25)
        newURL = browser.find_element_by_name("e64ca815")  #FirmwareURL
        newURL.clear()
        newURL.send_keys('@begin IF ( $FWV >= 3.1.2.5998 ) EXIT; @start SET TPRM2 = 2;        FWU -T=TPRM2 http://fw.obihai.com/OBi202-3-2-2-5921EX-332148940.fw;        IF ( $TPRM2 != 0 ) EXIT;        WAIT 60;        GOTO start;')
        isChecked = browser.find_element_by_name('46eb45e6usedefault').get_attribute('checked')
        if isChecked == 'true':
            browser.find_element_by_name('46eb45e6usedefault').click()  # uncheck "Default" for Method
        select = Select(browser.find_element_by_name('46eb45e6'))
        select.select_by_visible_text('System Start')

        browser.find_element_by_name('btn_sub').click()
        time.sleep(0.5)
        # click OK
        obj = browser.switch_to.alert
        obj.accept()

        # click Return
        browser.find_element_by_name('Return').click()

        Pd1.url = browser.find_element_by_name("7f7d0175").get_attribute("value").strip()
        Pd1.static = Select(browser.find_element_by_name('79d6d10d')).first_selected_option.get_attribute("text")

        browser.get('http://' + ip )
        time.sleep(0.5)
        browser.switch_to.frame('main_frame')
        Pd1.mac = browser.find_element_by_xpath("/html/body/div[@class='content']/form[1]/table[@class='xsltable'][2]/tbody[2]/tr[2]/td[@class='Tbl1_td2'][2]").text.replace(':', '').strip()
        Pd1.version = browser.find_element_by_xpath("/html/body/div[@class='content']/form[1]/table[@class='xsltable'][2]/tbody[2]/tr[6]/td[@class='Tbl1_td2'][2]").text.strip()
        Pd1.model = browser.find_element_by_xpath("/html/body/div[@class='content']/form[1]/table[@class='xsltable'][2]/tbody[2]/tr[1]/td[@class='Tbl1_td'][2]").text.strip()


    except Exception as e:
        Pd1.status = str(e.msg)
        if Pd1.status.find('TIMED_OUT') > -1 or Pd1.status.find('timeout') > -1:
            Pd1.status = 'timed out'
        elif browser.page_source == '<html><head></head><body></body></html>':
            Pd1.status = 'login failed'

    return Pd1



from selenium import webdriver
from selenium.webdriver.support.ui import Select
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
chromedriver = '/usr/local/bin/chromedriver'
opts = Options()
opts.headless = True
opts.add_argument('--ignore-ssl-errors=yes')
opts.add_argument('--ignore-certificate-errors')
opts.add_argument("--log-level=3")

try:
    browser = Chrome(options=opts, executable_path='chromedriver')
    browser.set_page_load_timeout(10)
except Exception as e:
    print(str(e.msg))
    print('Google Chrome has been updated.  download a new version of the chromedriver that matches the Current browser version above:   https://chromedriver.chromium.org/downloads')
    exit();

ip = socket.gethostbyname(socket.gethostname())
target_ip = ip[0:10].strip() + "1/24"  # pull the 192.168.x. out of the local ip.  won't work on 192.168.xx. without additional logic

scanIP(target_ip, browser)

browser.close()

exit()
