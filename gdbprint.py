from __future__ import print_function

import gdb
import string
class PrettyPrintString (gdb.Command):
    "Command to print strings with a mix of ascii and hex."

    def __init__(self):
        super (PrettyPrintString, self).__init__("ascii-print",
                gdb.COMMAND_DATA,
                gdb.COMPLETE_EXPRESSION, True)
        gdb.execute("alias -a ascp = ascii-print", True)

    def invoke(self, arg, from_tty):
        arg = arg.strip()
        if arg == "":
            print("Argument required (starting display address).")
            return
        startingAddress = gdb.parse_and_eval(arg)
        p = 0
        print('"', end='')
        while startingAddress[p] != ord("\0"):
            charCode = int(startingAddress[p].cast(gdb.lookup_type("char")))
            if chr(charCode) in string.printable:
                print("%c" % chr(charCode), end='')
            else:
                print("\\x%x" % charCode, end='')
            p += 1
        print('"')

PrettyPrintString()
