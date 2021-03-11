import pykd
import argparse
from enum import Enum, auto

class Module:
    # 00400000 00465000   diskpls    (deferred)
    def __init__(self, unparsed):
        self.name = 'unknown'
        self.start = -1
        self.end = -1
        self.unparsed = unparsed.split()
        self.parse()

    def parse(self):
        if len(self.unparsed) >= 3:
            self.start = self.unparsed[0]
            self.end = self.unparsed[1]
            self.name = self.unparsed[2]

    def __str__(self):
        return f'{self.name}(start={self.start}, end={self.end})'

class PopR32(Enum):
    eax = 0x58
    ecx = auto()
    edx = auto()
    ebx = auto()
    esp = auto()
    esi = auto()
    edi = auto()

def main(args):
    modules = pykd.dbgCommand('lm')

    for mod_line in modules.splitlines():
        module = Module(mod_line)

        if module.name.lower() not in [mod.lower() for mod in args.modules]:
            continue

        print(f'[+] searching {module.name} for pop r32; pop r32; ret')

        for pop1 in range(0x58, 0x60):

            for pop2 in range(0x58, 0x60):
                command = f's-[1]b {module.start} {module.end} {hex(pop1)} {hex(pop2)} c3'
                result = pykd.dbgCommand(command)
                
                
                if result is None:
                    continue

                for addr in result.splitlines():
                    try:
                        print(f'[+] {module.name}::{addr}: pop {PopR32(pop1).name}; pop {PopR32(pop2).name}; ret')
                    except ValueError:
                        # not a valid pop r32
                        pass



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('modules', help='module(s) name to search for pop pop ret', nargs='+')
    args = parser.parse_args()
    main(args)