#!/usr/bin/python

#
# This project is hosted at: https://code.google.com/p/mpssh-py/
# Please review the license and other info there.
#

prog_version = '1.0'

import os
import sys
import time
import datetime
import select
import pwd
import signal
import argparse

from subprocess import Popen, PIPE
from multiprocessing import Process, Queue, Lock
import multiprocessing.sharedctypes

settings = None

def usage_and_parse_argv():
	#
	# NOTE: If you change anything here, update the UsageHelp Wiki page.
	#

	parser = argparse.ArgumentParser(
		description='Executes an SSH command simulatenously on many hosts.',
		formatter_class=argparse.ArgumentDefaultsHelpFormatter
	)

	parser.add_argument('-f', '--file', help='name of the file with the list of hosts',
		default=None, required=True, type=str)
	#parser.add_argument('-o', '--outdir', help='save the remote output in this directory',
	#	default=None, required=False, type=str)
	parser.add_argument('-d', '--delay', help='delay between each SSH fork',
		default=50, required=False, type=int, metavar='MSEC')
	parser.add_argument('-e', '--zeroexit', help='print also zero remote command exit codes',
		action='store_true', required=False)
	parser.add_argument('-E', '--ignexit', help='ignore non-zero remote command exit codes',
		action='store_true', required=False)
	parser.add_argument('-p', '--procs', help='number of parallel SSH processes',
		default=100, required=False, type=int, metavar='NPROC')
	parser.add_argument('-u', '--user', help='force SSH login as this username',
		default='use current user', required=False, type=str)
	parser.add_argument('-l', '--maxlen', help='maximum length of output lines',
		default=80, required=False, type=int, metavar='CHARS')
	parser.add_argument('-S', '--sshbin', help='SSH binary path',
		default=which('ssh', '/usr/bin/ssh'), required=False, type=str)
	default_ssh_opt = [ # without the leading dash
		'o NumberOfPasswordPrompts=0'
	]
	parser.add_argument('-O', '--sshopt',
		help='additional options to pass to SSH; may be specified many times; skip the leading dash',
		default=default_ssh_opt, required=False, type=str, action='append')
	parser.add_argument('-H', '--noheader', help='do not show the header info',
		action='store_true', required=False)
	parser.add_argument('-v', '--verbose', help='be more verbose',
		action='store_true', required=False)
	parser.add_argument('-D', '--debug', help='show debug traces',
		action='store_true', required=False)
	parser.add_argument('-V', '--version', action='version', version='MPSSH.py %s' % prog_version)
	parser.add_argument('command', help='SSH command to mass-execute',
		default=None, type=str)

	return parser.parse_args()

def debug(level, sysname, message, pid=None):
	if not settings.debug:
		return
	if pid is None:
		pid=os.getpid()
	now = datetime.datetime.now()
	print "%s [%s %5d] %s" % (now.strftime('%Y-%m-%d %H:%M:%S'), sysname, pid, message)

# http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python/377028#377028
def which(program, default_path = None):
	def is_exe(fpath):
		return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

	fpath, fname = os.path.split(program)
	if fpath:
		if is_exe(program):
			return program
	else:
		for path in os.environ["PATH"].split(os.pathsep):
			path = path.strip('"')
			exe_file = os.path.join(path, program)
			if is_exe(exe_file):
				return exe_file

	return default_path


# http://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python
def read_nb(pipe): # XXX: Works only on UNIX (http://docs.python.org/2/library/select.html)
	retVal = ''
	while (select.select([pipe], [], [], 0.2)[0] != []):
		ch = pipe.read(1)
		if ch == '':
			break # we got EOF
		retVal += ch
	return retVal

def get_separator(t):
	separators = {
		'OUT': ["->", "\033[1;32m->\033[0;39m"],
		'ERR': ["=>", "\033[1;31m=>\033[0;39m"],
		'ECO': ["=:", "\033[1;32m=:\033[0;39m"], # exit code OK (ECO)
		'ECE': ["=:", "\033[1;31m=:\033[0;39m"], # exit code error (ECE)
	}
	color = 0
	if os.isatty(sys.stdout.fileno()):
		color = 1
	return separators[t][color]

def split_len(seq, length):
	if len(seq) == 0:
		return [''] # or else we skip empty lines
	return [seq[i:i+length] for i in range(0, len(seq), length)]

def print_host_output(max_host_len, host, separator, text):
	for line in text.splitlines():
		for short_line in split_len(line, settings.maxlen):
			print "%-*s %s %s" % (max_host_len, host, separator, short_line)

def sleep_sigsafe(t): # a sleep() safe to signal interruption; if we got interrupted and slept less, we'll sleep again
	want_t = time.time() + float(t)
	while True:
		diff = want_t - time.time()
		if diff <= 0.0:
			break
		time.sleep(diff)

def worker(input, max_host_len, counter_lock, processed_hosts, zero_ec_hosts, nonzero_ec_hosts, failed_ssh_hosts, got_sigint):
	# http://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
	def signal_handler(signal, frame):
		for i in range(10): # wait a bit for the parent to update the flag
			if got_sigint.value:
				break
			sleep_sigsafe(0.1)
		if not got_sigint.value: # did the parent got SIGINT too? if not -> bail out verbosely
			sys.stderr.write("\nERROR: Child: Terminated by CTRL+C!\n\n")
		sys.exit(1) # by default: exit silently => it won't be nice to see hundreds of errors by every worker
	signal.signal(signal.SIGINT, signal_handler)

	for host in iter(input.get, '*STOP*'):
		debug(2, 'worker', 'Begin processing (host: %s)' % host)
		with counter_lock:
			processed_hosts.value += 1
		sleep_sigsafe(float(settings.delay)/float(1000))

		cmd = []
		cmd.append(settings.sshbin)
		cmd += settings.sshopt
		cmd.append('%s@%s' % (settings.user, host))
		cmd.append(settings.command)

		# http://docs.python.org/2/library/subprocess.html
		try:
			p = Popen(
				cmd,
				bufsize=0, executable=None,
				stdin=None, stdout=PIPE, stderr=PIPE,
				preexec_fn=None, close_fds=False,
				shell=False,
				cwd=None, env=None,
				universal_newlines=False, startupinfo=None, creationflags=0
			)
		except OSError as e: # http://docs.python.org/2/tutorial/errors.html
			with counter_lock:
				failed_ssh_hosts.value += 1
			print_host_output(max_host_len, host, get_separator('ECE'),
				'exec(%s) error(%d): %s' % (cmd[0], e.errno, e.strerror)
			)
			continue
		debug(2, 'worker', 'Forked PID %d' % p.pid)

		while True:
			p.poll() # check if child exited and set "returncode"
			for t in ['OUT', 'ERR']:
				if t == 'OUT':
					pipe = p.stdout
				elif t == 'ERR':
					pipe = p.stderr
				else:
					raise Exception('Bad type: %s' % t)
				s = read_nb(pipe)
				if not len(s):
					continue
				print_host_output(max_host_len, host, get_separator(t), s)
			if p.returncode is None: # child is still working
				# in theory, we should have slept enough in read_nb()'s select()
				# but in practice select() immediately returns if we have EOF
				sleep_sigsafe(0.2)
				continue

			if (p.returncode != 0):
				if p.returncode > 0:
					do_print = False
					more_info = ''
					if p.returncode == 255: # exit code 255 (ssh indicates an error this way)
						with counter_lock:
							failed_ssh_hosts.value += 1
						do_print = True # this is always printed
						more_info = ' (possible SSH failure)'
					else:
						with counter_lock:
							nonzero_ec_hosts.value += 1
						if not settings.ignexit:
							do_print = True
					if do_print:
						print_host_output(max_host_len, host, get_separator('ECE'),
							'SSH exit code %d%s' % (p.returncode, more_info)
						)
				else: # killed
					with counter_lock:
						failed_ssh_hosts.value += 1

					# these errors are always displayed
					print_host_output(max_host_len, host, get_separator('ECE'),
						'SSH killed with signal %d' % -p.returncode
					)
			else: # p.returncode == 0
				with counter_lock:
					zero_ec_hosts.value += 1
				if settings.zeroexit:
					print_host_output(max_host_len, host, get_separator('ECO'),
						'SSH exit code %d' % p.returncode
					)
			debug(2, 'worker', 'Exit child (return code: %d)' % p.returncode)
			break

		debug(2, 'worker', 'End processing')
	debug(2, 'worker', 'Exit; nothing more to process in queue')
# end: def worker()

if __name__ == '__main__':
	def signal_handler(signal, frame):
		got_sigint.value = 1
		sys.stderr.write("\nERROR: Terminated by CTRL+C! Cleaning up, wait a few seconds.\n\n")
		sleep_sigsafe(3) # wait a bit for the children to terminate too
		sys.exit(1)
	signal.signal(signal.SIGINT, signal_handler)

	settings = usage_and_parse_argv()

	# http://docs.python.org/2/library/multiprocessing.html#multiprocessing.Process
	host_queue = Queue()
	max_host_len = 0
	host_count = 0
	for line in open(settings.file):
		host = line.strip()
		if not len(host) or host[0] == '#':
			continue # skip empty lines and comments
		if len(host) > max_host_len:
			max_host_len = len(host)
		host_queue.put(host)
		host_count += 1

	if settings.procs > host_count: # don't spawn more than we need, even if we're allowed to
		settings.procs = host_count

	if settings.user == 'use current user':
		settings.user = pwd.getpwuid(os.getuid())[0]

	for i in range(len(settings.sshopt)):
		settings.sshopt[i] = '-%s' % settings.sshopt[i]

	#if settings.outdir is not None:
	#	if not os.access(settings.outdir, os.F_OK): # if dir not exists
	#		os.mkdir(settings.outdir)

	if not settings.noheader:
		print 'MPSSH.py - Mass parallel SSH in Python (Version %s)' % prog_version
		print '(c) 2013 Ivan Zahariev <famzah>'
		print ''
		print '  [*] read (%d) hosts from the list' % host_count # Queue.qsize() returns the approximate size
		print '  [*] executing "%s" as user "%s"' % (settings.command, settings.user)
	if not settings.noheader and settings.verbose:
		print '  [*] SSH binary : %s' % (settings.sshbin)
		print '  [*] SSH options: %s' % (settings.sshopt)
	if not settings.noheader:
		print '  [*] spawning %d parallel SSH sessions' % settings.procs
	#if not settings.noheader and settings.outdir is not None:
	#	print '  [*] using output directory : %s' % settings.outdir
	if not settings.noheader:
		print ''

	for i in range(settings.procs):
		host_queue.put('*STOP*')

	# http://stackoverflow.com/questions/1233222/python-multiprocessing-easy-way-to-implement-a-simple-counter
	counter_lock = Lock()

	# shared memory variables
	processed_hosts = multiprocessing.sharedctypes.Value('i', 0)
	zero_ec_hosts = multiprocessing.sharedctypes.Value('i', 0)
	nonzero_ec_hosts = multiprocessing.sharedctypes.Value('i', 0)
	failed_ssh_hosts = multiprocessing.sharedctypes.Value('i', 0)
	got_sigint = multiprocessing.sharedctypes.Value('i', 0)

	procs_list = []
	for i in range(settings.procs):
		sleep_sigsafe(float(settings.delay)/float(1000))
		p = Process(target=worker, args=(
			host_queue, max_host_len, counter_lock, processed_hosts,
			zero_ec_hosts, nonzero_ec_hosts, failed_ssh_hosts, got_sigint
		))
		p.start()
		procs_list.append(p)
	
	while len(procs_list): # reap workers
		for p in procs_list:
			if p.exitcode is None: # child is still alive
				continue
			p.join()
			procs_list.remove(p)
		sleep_sigsafe(0.2)

	if not settings.noheader:
		print ''
		print '  Done. %d hosts processed (ok/non-ok/ssh-failed = %d/%d/%d).' % (
			processed_hosts.value, zero_ec_hosts.value, nonzero_ec_hosts.value, failed_ssh_hosts.value)

	# some paranoid sanity checks follow
	if processed_hosts.value != host_count:
		raise Exception(
			'ERROR: Sanity check failed. Processed hosts = %s but host count = %s' %
			(processed_hosts.value, host_count)
		)

	if (zero_ec_hosts.value + nonzero_ec_hosts.value + failed_ssh_hosts.value) != host_count:
		raise Exception('ERROR: Sanity check failed. Count sum of hosts info doesn\'t equal host count')
