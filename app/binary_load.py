import angr
import logging as log
import json
import copy


class Binary:

    def __init__(self, path, args):
        log.info("loading file {}".format(path))
        self.proj = angr.Project(
            path, load_options={"auto_load_libs": args.shared})
        log.debug("loading ok")
        self.loader = self.proj.loader
        self.target = self.loader.main_bin
        self.symbols = {}
        self.infos = {}
        log.info("start extracting informations from binary")
        self.populate()

    def __repr__(self):
        return json.dumps(
            {
                "name": self.proj.filename,
                "arch": self.infos["arch"],
                "objects": [x.binary for x in self.infos["loaded"]],
            },
            indent=4
        )

    def populate(self):
        log.info("extracting meta")
        self.load_infos()
        log.info("recovering main program CFG")
        self.build_cfg()
        log.info("extracting symbols")
        self.lookup_symbols()
        log.info("Extract artifacts from CFG")
        try:
            self.extract_artefacts_from_func()
        except Exception as e:
            print(e.message)

    def load_infos(self):
        self.infos["arch"] = str(self.proj.arch)
        self.infos["loaded"] = self.loader.all_elf_objects

    def lookup_symbols(self):
        # dumping function symbols only from main binary
        for addr, symbol in self.proj.kb.functions.iteritems():
            log.debug("found symbol {}".format(symbol.name))
            self.symbols[symbol.name] = symbol
        log.info("found {} symbols".format(len(self.symbols)))

    def build_cfg(self):
        self.infos["cfg"] = self.proj.analyses.CFGAccurate(
            starts=[self.proj.loader.main_bin.entry], keep_state=True)
        self.infos["cfg_normalized"] = copy.deepcopy(self.infos["cfg"])
        self.infos["cfg_normalized"].normalize()

    def extract_artefacts_from_func(self):
        self.infos["vfg"] = {}
        for name, symbol in self.symbols.items():
            if len(symbol.graph) == 1:
                log.warning("Symbol {} follow an unresolved jump\
                            skipping this symbol".format(symbol.name))
                continue
            log.info("Extracting VFG from symbol {}".format(name))
            self.infos["vfg"][name] = self.proj.analyses.VFG(
                cfg=self.infos["cfg_normalized"],
                start=symbol.addr)
            if len(self.infos["vfg"][name].graph) == 1:
                log.error("Can't build VFG for function {}, \
                          this might be due to an unresolved jump \
                          (non loaded binaries)".format(name))
                del self.infos["vfg"][name]
            else:
                log.info("Build improved CFG of {} nodes for symbol {}".format(
                    len(self.infos["vfg"][name].graph), name))


def load_array(args):
    bins = []
    for path in args.binaries[0]:
        try:
            proj = Binary(path, args)
        except Exception as e:
            log.error("Can't load binary {} due to:\n[{}]\n{}\n".format(
                path,
                str(type(e)),
                e.args[0]))
        else:
            bins.append(proj)
            print(bins[-1].__repr__())
    return bins
