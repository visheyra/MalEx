import angr
import claripy
import logging as log
import json
import copy


class Binary:

    def __init__(self, path, args):
        log.info("loading file {}".format(path))
        self.proj = angr.Project(
            path, load_options={"auto_load_libs": args.shared})
        log.debug("loading ok")
        self.filename = self.proj.filename
        self.loader = self.proj.loader  # CLE loader from angr
        self.target = self.loader.main_bin  # References to the main binary
        # All functions symbols avilable within the main binary
        self.symbols = {}
        # Finite automata which represents a graph
        self.fcg = {}
        self.cfg = None  # CFG of the program
        self.n_cfg = None  # CFG after normalization
        # Dict where keys are funtions name and values are VFG Graph from angr
        self.vfg = {}
        # Bunch of random stuff for anything that shouldn't be a property
        self.infos = {}
        log.info("start extracting informations from binary")
        self.populate()

    def get_results(self):
        return (
            self._gen_header_result(),
            self._gen_functions_result(),
            self._gen_calling_graph_result()
        )

    def _gen_header_result(self):
        return {
            "name": self.proj.filename,
            "arch": self.infos["arch"],
            "metas": {},
            "artefacts": {
                key.encode("utf-8"): {"symbol_name": func.name.encode("utf-8")}
                for key, func in self.symbols.items()
            }
        }

    def _build_instructions(self, node):
        block = self.proj.factory.block(
            addr=node.addr, size=node.size)
        data = []
        for i in block.capstone.insns:
            try:
                data.append({
                    "mnemonic": i.insn.mnemonic.encode("utf-8"),
                    "op_str": i.insn.op_str.encode("utf-8"),
                    "offset": "0x%08x" % i.insn.address})
            except Exception as e:
                log.error(e)
        return data

    def _build_value_set(self, node, func):
        s = claripy.Solver()

        data = {}
        # Get vfg

        vfg = None
        log.info("obtaining VSA of {}".format(func.name))
        try:
            vfg = self.vfg[func.name]
        except KeyError:
            log.error("function {} is unresolved skipping ...")
            return []

        # iterate node per node (logic block) to get VSA states per block
        for n in vfg.graph:
            if n.addr != node.addr:
                continue
            # iterate over all the possible states
            log.info("Currently on node {:08x}".format(n.addr))
            for st in n.all_states:

                # iterate over all the register whether they
                # are uninitiliased or platform specific
                for reg in dir(st.regs):

                    r = getattr(st.regs, reg)
                    if r.uninitialized:
                        continue
                    log.info("solving value set in register {}".format(reg))
                    data[reg] = []
                    data[reg].append({
                        "min": "{:08x}".format(s.min(getattr(st.regs, reg))),
                        "max": "{:08x}".format(s.max(getattr(st.regs, reg)))
                    })
        print(data)
        return data

    def _gen_functions_result(self):
        return [{
                "name": name.encode("utf-8"),
                "datas": {
                    "metas": {
                        "start": "0x%08x" % func.addr,
                        "size": len(func.graph)
                    },
                    "nodes": [{
                        "address": "0x%08x" % node.addr,
                        "step": int(node.addr - func.addr),
                        "instruction": self._build_instructions(node),
                        "VSA": self._build_value_set(node, func)
                    } for node in func.graph]
                }} for name, func in self.symbols.items()]

    def _gen_calling_graph_result(self):
        return self.fcg

    def __repr__(self):
        return json.dumps(
            {
                "name": self.proj.filename,
                "arch": self.infos["arch"],
                "objects": [x.binary for x in self.infos["loaded"]],
                "calling graph": self.fcg
            },
            indent=4
        )

    def generate_function_calling_graph(self):
        for name, func in self.symbols.items():
            log.info("Found that function {} is called {} \
                     times".format(func.name, len(func.get_call_sites())))
            for call in func.get_call_sites():
                try:
                    t_addr = func.get_call_target(call)
                    t_func = self.proj.kb.functions[t_addr]
                    func_name = func.name.encode("utf-8")
                    t_func_name = t_func.name.encode("utf-8")
                    self.fcg[func_name]["callees"].append(
                        t_func_name
                    )
                    self.fcg[t_func_name]["callers"].append(
                        func_name
                    )
                    self.fcg[func_name]["offset"] = "0x%08x" % func.addr
                    log.debug("found link between {} and {}")
                except KeyError:
                    log.error("Can't find symbol at {}".format(hex(t_addr)))

    def __graph__(self):
        """
        output binary informations as a bunch of graphs
        """
        return {
            "cfg": self.cfg.graph,
            "functions": {
                k: v.graph for k, v in self.vfg.items()
            }
        }

    def populate(self):
        log.info("extracting meta")
        self.load_infos()
        log.info("recovering main program CFG")
        self.build_cfg()
        log.info("extracting symbols")
        self.lookup_symbols()
        log.info("Extract calling function graph")
        self.generate_function_calling_graph()
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
            self.fcg[symbol.name.encode("utf-8")] = {
                "offset": None,
                "callers": [],
                "callees": []
            }
        log.info("found {} symbols".format(len(self.symbols)))

    def build_cfg(self):
        self.cfg = self.proj.analyses.CFGAccurate(
            starts=[self.proj.loader.main_bin.entry], keep_state=True)
        self.n_cfg = copy.deepcopy(self.cfg)
        log.debug("Normalizing CFG")
        self.n_cfg.normalize()

    def extract_artefacts_from_func(self):
        for name, symbol in self.symbols.items():
            if len(symbol.graph) == 1:
                log.warning("Symbol {} follow an unresolved jump\
                            skipping this symbol".format(symbol.name))
                continue
            log.info("Extracting VFG from symbol {}".format(name))
            self.vfg[name] = self.proj.analyses.VFG(
                cfg=self.n_cfg,
                start=symbol.addr)
            if len(self.vfg[name].graph) == 1:
                log.error("Can't build VFG for function {}, \
                          this might be due to an unresolved jump \
                          (non loaded binaries)".format(name))
                del self.vfg[name]
            else:
                log.info("Build improved CFG of {} nodes for symbol {}".format(
                    len(self.vfg[name].graph), name))


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
    return bins
