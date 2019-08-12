import re
import json
import glob
import argparse
from collections import namedtuple

parser = argparse.ArgumentParser(description='Scan code for potential issues')
parser.add_argument('code_path', type=str, help='The directory where your code resides')
args = parser.parse_args()

# Get all the files in the path desired
print("[+] Gathering files from {} to scan.".format(args.code_path))
code_path = args.code_path
if code_path.endswith('/'):
    code_path = args.code_path+"*.*"
else:
    code_path = args.code_path+"/*.*"
files = glob.glob(code_path)

# Escapes special characters so they can be used in regex strings
def escape_special(value):
    value = value.replace('(','\(')
    return value

# Load all the search signatures
print("[+] Loading signatures...")
with open('signatures.json', 'rb') as p:
    signatures = json.load(p)

findings = 0
file_count = 0
for f in files:
    file_count += 1
    line_num = 1
    with open(f) as t:
        line = t.readline()
        while line:
            line = t.readline()
            for s in signatures:
                data = json.dumps(s)
                sig = json.loads(data, object_hook=lambda d: namedtuple('pattern', d.keys())(*d.values()))
                for search in sig.patterns:
                    matches = re.findall(r'(^.*'+escape_special(search)+'.*)', line, re.DOTALL)
                    if(matches):
                        print('[!] Possible code issue in {} on line {}. {} Line content: \'{}\''.format(f, line_num, sig.issue, line.strip()))
                        findings += 1
            line_num += 1
        t.close()

print("[-] Found {} potential issues across {} files.".format(findings, file_count))
