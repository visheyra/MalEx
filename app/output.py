import os
import yaml
import logging as log


class output_binary:

    def __init__(self, output_dir, create=False, erase=True):
        self.output_dir = output_dir
        self.create = create
        self.erase = erase
        self.binaries = {}

    def feed(self, binary):
        self.binaries[binary.proj.filename] = binary

    def verify(self):
        print(os.path.exists(os.path.join(os.getcwd(), self.output_dir)))
        if not os.path.exists(os.path.join(os.getcwd(), self.output_dir)):
            log.warning("output directory doesn't exists")
            if self.create:
                os.makedirs(os.path.join(os.getcwd(), self.output_dir))
            else:
                log.error("Can't create output directory (use -c ?)")
                raise IOError("Can't create directory")

    def output(self):
        try:
            self.verify()
        except IOError:
            log.error("Can't output to disk, \
                      will diplay informations on stdout")
        for n, b in self.binaries.items():
            folder_name = "analyse_{}".format(
                n.replace("/", "_"))
            folder_path = os.path.join(
                os.getcwd(),
                self.output_dir,
                folder_name
            )
            log.error(folder_path)
            os.makedirs(folder_path)
            h, fs, c = b.get_results()
            for f in fs:
                h["artefacts"][f["name"]]["filename"] = "{}.yml".format(f["name"])
                # Dump functions one per one
                with open(os.path.join(folder_path, "{}.yml".format(f["name"])), "w+") as fd:
                    fd.write(yaml.dump(f, default_flow_style=False))
            log.error("opening header file {}".format(os.path.join(folder_path, "header.yml")))
            # Dump header file
            with open(os.path.join(folder_path, "header.yml"), "w+") as fd:
                fd.write(yaml.dump(h, default_flow_style=False))
            # Dump FCG
            with open(os.path.join(folder_path, "funct_call_graph.yml"), "w+") as fd:
                fd.write(yaml.dump(c, default_flow_style=False))
