#!/usr/bin/env python
# theymos (Michael Marquardt)
# Public domain
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

from passlib.hash import sha512_crypt
from passlib.utils import ab64_encode, ab64_decode
from hashlib import sha512
import sys
import json
import unicodedata
import getpass
import getopt

PASSPHRASE_ROUNDS = 1000000

salt_questions = [
	'The full name you were given as a child',
	'4-digit year in which you were born',
	'2-digit month in which you were born',
	'2-digit date in which you were born',
	'City where you were born (do not include state, country, etc.)',
	'Other salt (not recommended)'
]
# verify answers to salt questions to prevent confusion about exact formats
salt_verification = [
	lambda x: True,
	lambda x: len(x) == 0 or (len(x) == 4 and x.isdigit()),
	lambda x: len(x) == 0 or (len(x) == 2 and x.isdigit()),
	lambda x: len(x) == 0 or (len(x) == 2 and x.isdigit()),
	lambda x: True,
	lambda x: True,
]

# Hash passphrase using salt
def generate_key( passphrase, salt ):
	assert len(passphrase) > 0
	
	# add salt to passphrase and to sha512_crypt's salt
	crypt_salt = ab64_encode(sha512(salt).digest())[:16]
	passphrase += salt
	
	assert len(crypt_salt) == 16	
	key = sha512_crypt.encrypt(passphrase, rounds = PASSPHRASE_ROUNDS, salt = crypt_salt)
	assert len(key) > 86
	
	# get just the hash back
	key = ab64_decode(key[-86:])
	
	assert len(key) == 64	
	return key

# Expand or truncate key to bytes
def expand_key ( key, bytes ):
	if len(key) >= bytes:
		return key[:bytes]
	
	out = ''
	i = 0
	while len(out) < bytes:
		out += sha512(key + str(i)).digest()
		i += 1
		
	return out[:bytes]

def in_prompt ( prompt ):
	sys.stderr.write(prompt)
	return sys.stdin.readline().rstrip('\n')

def help ():
	print >> sys.stderr, """
Securely computes a key from a passphrase and salt.

-b --output-bytes=N  Number of bytes to output. The default is 32,
                     the number of bytes in a Bitcoin private key.
-s --salt-file=FILE  The file to save salt info in. The default is
                     ./salt. An empty string or '/dev/null' will
                     disable writing a salt file.
-e --echo            Echo the passphrase.
--help               Show this help.
"""

def input_normalized( prompt, echo = True):
	if echo:
		answer = in_prompt(prompt)
	else:
		answer = getpass.getpass(prompt)
	answer = unicode(answer, sys.stdin.encoding)
	answer = answer.strip()
	answer = unicodedata.normalize('NFC', answer)
	return answer
	
try:
	opts = getopt.getopt(sys.argv[1:], 'b:s:o:e', ['output-bytes=', 'salt-file=', 'output-format=', 'help', 'echo'])[0]
except getopt.GetoptError as err:
	print >> sys.stderr, "Invalid option\n"
	help()
	sys.exit(2)

# defaults
output_bytes = 32
salt_file = './salt'
echo = False

for o, a in opts:
	if o == '--help':
		help()
		sys.exit(2)
	elif o in ('-b', '--output-bytes'):
		output_bytes = int(a)
	elif o in ('-s', '--salt-file'):
		salt_file = a
	elif o in ('-e', '--echo'):
		echo = True
	
write_salt = True
if salt_file in ('', '/dev/null'):
	write_salt = False

# read salt file if it exists
salt = None
if write_salt:
	try:
		salt = json.loads(open(salt_file, 'r').read())
		for q in range(0, len(salt_questions)):
			if salt[q][0] != salt_questions[q]:
				raise Exception()
		have_salt_file = True
	except:
		salt = None
		have_salt_file = False
	
if salt is None:
	print >> sys.stderr, """========SALT========
Your answers to these questions will be added to your passphrase
in order to make attacks more difficult. It should be impossible
for you to forget your answers to these questions. You are not
trying to give answers that are difficult to guess. If you don't
want to answer any of the questions, leave them blank.
"""
	salt = []
	for q in range(0, len(salt_questions)):
		answer = input_normalized(salt_questions[q] + ": ")
		answer = answer.lower()
		if not salt_verification[q](answer):
			print >> sys.stderr, "Invalid answer"
			sys.exit(2)
		salt.append([salt_questions[q], answer])

print >> sys.stderr, """
========WALLET ID========
Optionally, you may use this field to create multiple wallets
from one passphrase and salt. For example, you could set this to
'personal' to get a key for a personal wallet and 'work' to get
a key for a work wallet.
"""
wallet_id = input_normalized("Wallet ID: ")
wallet_id = wallet_id.lower()

print >> sys.stderr, """
========PASSPHRASE========
A passphrase for Bitcoin must be much stronger than passphrases
for banks, etc. because everyone on Earth can and will try to
guess your passphrase.
"""

# Everything in salt/passphrase should be encoded as UTF-8
passphrase = input_normalized("Passphrase: ", echo)
if not passphrase:
	print >> sys.stderr, "Need a passphrase"
	sys.exit(2)
passphrase = passphrase.encode('utf-8')

crypt_salt = ''
print >> sys.stderr, "\n(everything but passphrase converted to lowercase)"
for q in salt:
	print >> sys.stderr, q[0] + ': <<' + q[1] + '>>'
	crypt_salt += q[1].encode('utf-8')
crypt_salt += wallet_id.encode('utf-8')
print >> sys.stderr, "Wallet ID: <<" + wallet_id + ">>"

if echo:
	print >> sys.stderr, "Passphrase: <<" + passphrase.decode('utf-8') + ">>"
	print >> sys.stderr, "Salt: <<" + crypt_salt.decode('utf-8') + ">>"
	print >> sys.stderr, "Passphrase (hex): <<" + passphrase.encode('hex') + ">>"
	print >> sys.stderr, "Salt (hex): <<" + crypt_salt.encode('hex') + ">>"

print >> sys.stderr, "\nCalculating key..."
key = expand_key(generate_key(passphrase, crypt_salt), output_bytes).encode('hex')
print >> sys.stderr, "Final key:"
print key

#Write salt
if write_salt and not have_salt_file:
	print >> sys.stderr, "Writing salt to '" + salt_file + "' ..."
	try:
		open(salt_file, 'w').write(json.dumps(salt))
	except Exception as e:
		print >> sys.stderr, "Writing salt failed: " + e.strerror
	else:
		print >> sys.stderr, "OK"
