''' Implements Linux command-line (Busybox) emulation for Kako. '''

import re
import binascii

from kako.simulation.server import error


class CommandInterpreter(object):
    ''' Implements commands for an embedded BusyBox system (Linux). '''
    version = 'Edimax IC-7113W v1.19.3 (2022-04-21 10:10:26 CST)'

    def do_id(self, args=None):
        ''' Returns `id` command output. '''
        if args is None:
            args = []
        return 'uid=0(root) gid=0(root) groups=0(root)'

    def do_exit(self, args=None):
        ''' Returns an exit signal to the caller. '''
        if args is None:
            args = []
        raise error.ClientCommandExit()

    def do_ls(self, args=None):
        ''' Stub `ls`. '''
        if args is None:
            args = []
        return

    def do_rm(self, args=None):
        ''' Stub `rm`. '''
        if args is None:
            args = []
        return

    def do_cp(self, args=None):
        ''' Stub `cp`. '''
        if args is None:
            args = []
        return

    def do_cd(self, args=None):
        ''' Stub `cd`. '''
        if args is None:
            args = []
        return

    def do_wget(self, args=None):
        ''' Stub `wget`. '''
        if args is None:
            args = []
        return

    def do_busybox(self, args=None):
        ''' Wrapper the handle() method to handle BusyBox applets. '''
        if args:
            result = self.handle(' '.join(args))
            if re.match(r'^sh:\s', result):
                return '{0}: applet not found'.format(args[0])
            else:
                return result
        else:
            return self.version

    def do_echo(self, args=None):
        ''' Returns the input as provided - sans 'arguments' '''
        if args is None:
            args = []

        # Remove any 'arguments' from echo only if contiguous and before any
        # other data.
        for idx, arg in enumerate(args):
            if arg.startswith('-'):
                del args[idx]
            else:
                break

        # Decode encoded characters.
        decoded_args = []
        for arg in args:
            if "\\x" in arg:
                try:
                    decoded_args.append(
                        re.sub(
                            r'\\x([0-9A-Z]{1,2})',
                            lambda x: binascii.unhexlify(x.group(1)).decode(),
                            arg,
                            flags=re.IGNORECASE
                        )
                    )
                except UnicodeDecodeError as _:
                    decoded_args.append(arg)
            else:
                decoded_args.append(arg)

        # Flag for quotes to be stripped, if they're matched.
        matched_double_quote = False
        matched_single_quote = False
        if not ''.join(decoded_args).count('"') % 2:
            matched_double_quote = True
        if not ''.join(decoded_args).count("'") % 2:
            matched_single_quote = True

        # Strip all quotes, if required, and return it.
        result = ' '.join(decoded_args).strip()
        result = result.replace('"', '') if matched_double_quote else result
        result = result.replace("'", '') if matched_single_quote else result
        return result.strip()

    def do_cat(self, args=None):
        ''' Implement expected Mirai files. '''
        if args is None:
            args = []
        if len(args) < 1:
            return

        # TELNET_DETECT_ARCH - Fake ELF header.
        if args[0] == '/bin/echo':
            return ''.join([
                '\x7F\x45\x4c\x46',                  # ELF magic.
                '\x01',                              # 32-Bit.
                '\x01',                              # Little Endian.
                '\x01',                              # Version 1.
                '\x03',                              # Linux ABI.
                '\x00\x00\x00\x00\x00\x00\x00\x00',  # Unused padding.
                '\x02',                              # Executable.
                '\x08'                               # MIPS.
            ])

        # TELNET_PARSE_MOUNTS - Fake read-write mount-point(s).
        if args[0] == '/proc/mounts':
            return 'rootfs / rootfs rw 0 0'

    def do_ps(self, args=None):
        ''' Implements Mirai expected processes. '''
        if args is None:
            args = []
        process_list = []
        process_list.append('PID   Uid    VmSize    Stat    Command\r\n')
        process_list.append('  1   root      404     S      init')
        return ''.join(process_list)

    def do_ifconfig(self, args=None):
        if args is None:
            args = []
        
        return """    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.14.123.158  netmask 255.255.240.0  broadcast 172.25.207.255
        inet6 fe80::215:5dff:fe69:f6fd  prefixlen 64  scopeid 0x20<link>
        ether 00:15:5d:69:f6:fd  txqueuelen 1000  (Ethernet)
        RX packets 4531  bytes 1121722 (1.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 254  bytes 35565 (35.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

    lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4114  bytes 8963416 (8.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4114  bytes 8963416 (8.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"""
        
    def do_tiltLeft(self, args=None):
        ''' Implements Mirai expected processes. '''
        if args is None:
            args = [0]
        
        return 'camera tilted left {args[0]} degree'
    
    def do_tiltRight(self, args=None):
        ''' Implements Mirai expected processes. '''
        if args is None:
            args = [0]
        
        return 'camera tilted right {args[0]} degree'
    
    def do_getVideo(self, args=None):
        ''' Implements Mirai expected processes. '''
        if args is None:
            args = [0]
        
        return 'Access Denied'
    
    #Attacker trying to turn on night vision mode
    def do_nightVisionMode(self, args=None):
        if args is None:
            args = [0]
        
        return 'Access Denied'

    #Attacker trying to turn on Tempearture detection
    def do_temDetect(self, args=None):
        if args is None:
            args = [0]
        
        return 'Access Denied'
        
    #Attacker trying to turn on Tempearture detection
    def do_motionDetect(self, args=None):
        if args is None:
            args = [0]
        
        return 'Access Denied'

    def do_mkdir(self, args=None):
        ''' Implements Mirai expected processes. '''
        if args is None:
            args = [0]
        
        return 'Command not found'
    
    def handle(self, commands):
        ''' Dispatches the input command to the relevant handler. '''
        # Split commands on semicolon, in the case there are multiple commands
        # on one line.
        output = ''
        sensitive = False
        for command in commands.split(';'):
            # Split command from arguments, and ensure we're left with at least
            # a command to execute.
            arguments = re.split(r'\s+', command.lstrip())
            if len(arguments) < 1:
                continue

            # Remove full path from command - if present - and attempt to call.
            command = arguments[0].split('/')[-1]
            sensitive = command == 'getVideo'
            arguments.pop(0)
            try:
                ref = getattr(self, "do_{0}".format(command))
            except AttributeError:
                if len(command) >= 1:
                    output += "sh: {0}: command not found\r\n".format(command)
                continue

            # Call the appropriate handler, and record the output.
            result = ref(arguments)
            if result:
                output += '{0}\r\n'.format(result.strip())
            else:
                output += '\r\n'

        return output, sensitive
