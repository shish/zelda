#!/usr/bin/python

import struct
import socket
import sys
import psyco ; psyco.full()


# from http://code.activestate.com/recipes/65219/
def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('!L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('!L',n))


def parse_line(line):
    (
        ip, dash1, dash2, fulldate, timezone,
        method, path, proto, status, bytes, other
    ) = line.strip().split(" ", 10)

    if dash1 != "-" or dash2 != "-":
        raise Exception("Bad format (dashes)")
    if fulldate[0] != "[" or timezone[-1] != "]":
        raise Exception("Bad format (timestamp)")
    if method[0] != "\"" or proto[-1] != "\"":
        raise Exception("Bad format (query)")
    if other[0] != "\"" or other[-1] != "\"":
        raise Exception("Bad format (other)")
    if bytes == "-":
        bytes = -1

    referrer, agent = other[1:-1].split('" "');
    (date, h, m, s) = fulldate[1:].split(":")
    timezone = timezone[:-1]
    method = method[1:]
    proto = proto[:-1]

    return (
        ip, date, h, m, s, timezone, method, path,
        proto, status, bytes, referrer, agent
    )


class Compressor:
    def __init__(self):
        self.status = 1
        self.datedict = {}
        self.methoddict = {}
        self.pathdict = {}
        self.protodict = {}
        self.statusdict = {}
        self.referrerdict = {}
        self.agentdict = {}
        self.timezone_ = ""

        self.logfile = file(sys.argv[1])
        if len(sys.argv) == 3:
            self.outfile = file(sys.argv[2], "w")
        else:
            self.outfile = file(sys.argv[1]+".loz", "w")

        self.run()

        self.outfile.close()
        self.logfile.close()

        self.status = 0


    def run(self):
        self.build_dict()
        self.sort_dict()
        self.write_dict()
        self.write_log()


    def build_dict(self):
        print "Building dictionary"
        for linenum, line in enumerate(file(sys.argv[1])):
            if linenum % 100 == 0:
                print "%d\r" % linenum,
            try:
                (
                    ip, date, h, m, s, timezone, method, path,
                    proto, status, bytes, referrer, agent
                ) = parse_line(line)

                self.timezone_ = timezone
                self.datedict[date] = True
                self.methoddict[method] = True
                self.pathdict[path] = True
                self.protodict[proto] = True
                self.statusdict[status] = True
                self.referrerdict[referrer] = True
                self.agentdict[agent] = True
            except:
                pass



    def sort_dict(self):
        print "Sorting dictionary... "
        self.datekeys     = self.datedict.keys();     self.datekeys.sort()
        self.methodkeys   = self.methoddict.keys();   self.methodkeys.sort()
        self.pathkeys     = self.pathdict.keys();     self.pathkeys.sort()
        self.protokeys    = self.protodict.keys();    self.protokeys.sort()
        self.statuskeys   = self.statusdict.keys();   self.statuskeys.sort()
        self.referrerkeys = self.referrerdict.keys(); self.referrerkeys.sort()
        self.agentkeys    = self.agentdict.keys();    self.agentkeys.sort()

        print "Numbering dictionary elements..."
        for num, key in enumerate(self.datekeys):     self.datedict[key] = num
        for num, key in enumerate(self.methodkeys):   self.methoddict[key] = num
        for num, key in enumerate(self.pathkeys):     self.pathdict[key] = num
        for num, key in enumerate(self.protokeys):    self.protodict[key] = num
        for num, key in enumerate(self.statuskeys):   self.statusdict[key] = num
        for num, key in enumerate(self.referrerkeys): self.referrerdict[key] = num
        for num, key in enumerate(self.agentkeys):    self.agentdict[key] = num


    def write_dict(self):
        print "Writing header..."
        self.outfile.write("LOZ1\n")

        print "Writing dictionary... "
        print "bits ",
        self.outfile.write(self.timezone_+"\n")
        self.outfile.write(":".join(self.datekeys)+"\n")
        self.outfile.write(":".join(self.methodkeys)+"\n")
        self.outfile.write(":".join(self.statuskeys)+"\n")
        self.outfile.write(":".join(self.protokeys)+"\n")

        print "paths ",
        self.outfile.write(str(len(self.pathkeys))+"\n")
        for path in self.pathkeys:
            self.outfile.write(path+"\n")

        print "referrers ",
        self.outfile.write(str(len(self.referrerkeys))+"\n")
        for referrer in self.referrerkeys:
            self.outfile.write(referrer+"\n")

        print "agents ",
        self.outfile.write(str(len(self.agentkeys))+"\n")
        for agent in self.agentkeys:
            self.outfile.write(agent+"\n")

        print ""


    def write_log(self):
        print "Writing log"
        record_struct = struct.Struct("!LcccccLcclLL")
        for linenum, line in enumerate(file(sys.argv[1])):
            if linenum % 100 == 0:
                print "%d\r" % linenum,
            try:
                (
                    ip, date, h, m, s, timezone, method, path,
                    proto, status, bytes, referrer, agent
                ) = parse_line(line)

                self.outfile.write(record_struct.pack(
                    dottedQuadToNum(ip),
                    chr(self.datedict[date]),
                    chr(int(h)), chr(int(m)), chr(int(s)),
                    chr(self.methoddict[method]),
                    self.pathdict[path],
                    chr(self.protodict[proto]),
                    chr(self.statusdict[status]),
                    int(bytes),
                    self.referrerdict[referrer],
                    self.agentdict[agent],
                ))
            except Exception, e:
                #print e
                self.outfile.write(record_struct.pack(
                    dottedQuadToNum("0.0.0.1"),
                    chr(0),
                    chr(0), chr(0), chr(0),
                    chr(0),
                    0,
                    chr(0),
                    chr(0),
                    int(0),
                    0,
                    0,
                ))
                self.outfile.write(line.strip()+"\n")


class Decompressor:
    def __init__(self):
        self.status = 1

        self.datedict = []
        self.methoddict = []
        self.pathdict = []
        self.protodict = []
        self.statusdict = []
        self.referrerdict = []
        self.agentdict = []
        self.timezone = ""

        self.logfile = file(sys.argv[1])
        if len(sys.argv) == 3:
            self.outfile = file(sys.argv[2], "w")
        else:
            self.outfile = file(sys.argv[1]+".deloz", "w")

        self.run()

        self.outfile.close()
        self.logfile.close()

        self.status = 0


    def run(self):
        self.read_header()
        self.read_logs()


    def read_header(self):
        sig = self.logfile.readline().strip()
        if sig != "LOZ1":
            raise Exception("Invalid signature")

        self.timezone = self.logfile.readline().strip()
        self.datedict.extend(self.logfile.readline().strip().split(":"))
        self.methoddict.extend(self.logfile.readline().strip().split(":"))
        self.statusdict.extend(self.logfile.readline().strip().split(":"))
        self.protodict.extend(self.logfile.readline().strip().split(":"))

        for n in range(0, int(self.logfile.readline().strip())):
            self.pathdict.append(self.logfile.readline().strip())
        for n in range(0, int(self.logfile.readline().strip())):
            self.referrerdict.append(self.logfile.readline().strip())
        for n in range(0, int(self.logfile.readline().strip())):
            self.agentdict.append(self.logfile.readline().strip())


    def read_logs(self):
        record_struct = struct.Struct("!LcccccLcclLL")
        while True:
            data = self.logfile.read(record_struct.size)
            if len(data) == 0:
                break
            (ip, dateidx_c, h_c, m_c, s_c, methodidx_c, pathidx, protoidx_c,
            statusidx_c, bytes, referreridx, agentidx) = record_struct.unpack(data)

            if bytes == -1:
                bytes = "-"

            text_ip = numToDottedQuad(ip)
            if text_ip == "0.0.0.1":
                self.outfile.write(self.logfile.readline())
            else:
                self.outfile.write("%s - - [%s:%02d:%02d:%02d %s] \"%s %s %s\" %s %s \"%s\" \"%s\"\n" % (
                    text_ip,
                    self.datedict[ord(dateidx_c)], ord(h_c), ord(m_c), ord(s_c), self.timezone,
                    self.methoddict[ord(methodidx_c)], self.pathdict[pathidx], self.protodict[ord(protoidx_c)],
                    self.statusdict[ord(statusidx_c)], str(bytes),
                    self.referrerdict[referreridx], self.agentdict[agentidx]
                ))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print "Must specify a file to compress or decompress"
        sys.exit(2)
    if file(sys.argv[1]).readline() == "LOZ1\n":
        sys.exit(Decompressor().status)
    else:
        sys.exit(Compressor().status)

