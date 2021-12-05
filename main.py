#!/usr/bin/python3
import base64
import os
import sys
import socket
import json
import threading
import time
import uuid
from threading import Thread
import collections
import hashlib
import argparse
import dns.resolver


class SimpleLRUCache:
    def __init__(self, size):
        self.size = size
        self.id = uuid.uuid4()
        self.cache_lock = threading.Lock()
        self._lru_cache = collections.OrderedDict()

    def get(self, key):
        # print("DEBUG: Retrieving item (" + key + ") from cache (" + str(self.id) + ")...")
        with self.cache_lock:
            try:
                value = self._lru_cache.pop(key)
                self._lru_cache[key] = value
                return value
            except KeyError:
                return None, -1

    def __put(self, key, value):
        try:
            self._lru_cache.pop(key)
        except KeyError:
            if len(self._lru_cache) >= self.size:
                self._lru_cache.popitem(last=False)
        self._lru_cache[key] = value

    def put(self, key, value):
        # print("DEBUG: Appending item (" + value + ") to cache (" + str(self.id) + ")...")
        with self.cache_lock:
            self.__put(key, value)

    def put_if_not_exist(self, key, value):
        # print("DEBUG: Appending item (" + value + ") to cache (" + str(self.id) + ") if it does not exist...")
        with self.cache_lock:
            if key not in self._lru_cache:
                self.__put(key, value)

    def exists(self, key):
        print("DEBUG: Checking if item (" + key + ") exists in cache (" + str(self.id) + ")...")
        with self.cache_lock:
            return key in self._lru_cache

    def dump(self):
        # print("DEBUG: Dumping items from cache (" + str(self.id) + ")...")
        with self.cache_lock:
            return self._lru_cache.copy().items()

    def len(self):
        # print("DEBUG: Getting length of cache (" + str(self.id) + ")...")
        with self.cache_lock:
            return len(self._lru_cache)


class DnsRblsTesterServer:
    def __init__(self, socket_path, max_cache_size, max_dns_timeout=1, dns_rbls_list=None):
        if dns_rbls_list is None:
            dns_rbls_list = []
        self.socket_path = socket_path
        self.cache = SimpleLRUCache(max_cache_size)
        self.tasks_counter = 0
        self.time_taken_recent5 = []
        self.time_taken_recent15 = []
        self.time_taken_recent45 = []
        self.time_taken_mgmt_lock = threading.Lock()
        self.threads_count = 0
        self.threads_lock = threading.Lock()
        self.max_dns_timeout = max_dns_timeout
        self.dns_rbls_list = dns_rbls_list
        self.max_time_taken_ms = 0
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = max_dns_timeout
        if len(dns_rbls_list) == 0:
            self.dns_rbls_list = ['spam.spamrats.com', 'spamguard.leadmon.net', 'rbl-plus.mail-abuse.org', 'web.dnsbl.sorbs.net', 'ix.dnsbl.manitu.net', 'virus.rbl.jp', 'dul.dnsbl.sorbs.net', 'bogons.cymru.com', 'psbl.surriel.com', 'misc.dnsbl.sorbs.net', 'httpbl.abuse.ch', 'combined.njabl.org', 'smtp.dnsbl.sorbs.net', 'korea.services.net', 'drone.abuse.ch', 'rbl.efnetrbl.org', 'cbl.anti-spam.org.cn', 'b.barracudacentral.org', 'bl.spamcannibal.org', 'xbl.spamhaus.org', 'zen.spamhaus.org', 'rbl.suresupport.com', 'db.wpbl.info', 'sbl.spamhaus.org', 'http.dnsbl.sorbs.net', 'csi.cloudmark.com', 'rbl.interserver.net', 'ubl.unsubscore.com', 'dnsbl.sorbs.net', 'virbl.bit.nl', 'pbl.spamhaus.org', 'socks.dnsbl.sorbs.net', 'short.rbl.jp', 'dnsbl.dronebl.org', 'blackholes.mail-abuse.org', 'truncate.gbudb.net', 'dyna.spamrats.com', 'spamrbl.imp.ch', 'spam.dnsbl.sorbs.net', 'wormrbl.imp.ch', 'query.senderbase.org', 'opm.tornevall.org', 'netblock.pedantic.org', 'access.redhawk.org', 'cdl.anti-spam.org.cn', 'multi.surbl.org', 'noptr.spamrats.com', 'dnsbl.inps.de', 'bl.spamcop.net', 'cbl.abuseat.org', 'dsn.rfc-ignorant.org', 'zombie.dnsbl.sorbs.net', 'dnsbl.njabl.org', 'relays.mail-abuse.org', 'rbl.spamlab.com']


    def start(self):
        # Make sure the socket does not already exist
        try:
            os.unlink(self.socket_path)
        except OSError:
            if os.path.exists(self.socket_path):
                raise

        # Create a UDS socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Bind the socket to the address
        print('starting up on {}'.format(self.socket_path))
        sock.bind(self.socket_path)

        # Listen for incoming connections
        sock.listen(1)

        while True:
            # Wait for a connection
            connection, client_address = sock.accept()
            Thread(target=self.connection_handler, args=[connection]).start()

    def connection_handler(self, conn):
        avg_time_taken_recent5 = -1
        avg_time_taken_recent15 = -1
        avg_time_taken_recent45 = -1
        time_taken = -1
        with self.threads_lock:
            self.threads_count = self.threads_count + 1
        try:
            raw_data = conn.recv(1024)
            raw_data_string = raw_data.decode()
            command_obj = json.loads(raw_data.decode())
            if "text" not in command_obj:
                print("ERROR: Command misunderstood. Command: " + base64.b64decode(raw_data_string).decode())
                conn.sendall("ERROR: Command misunderstood".encode())
            else:
                time_started = time.time()
                # print("DEBUG: Handling " + raw_data_string)
                if self.cache.exists(command_obj["text"]):
                    result = json.loads(self.cache.get(command_obj["text"]))
                else:
                    result = self.check_against_dns_rbls(command_obj["text"])
                self.tasks_counter = self.tasks_counter + 1
                time_taken = time.time() - time_started
                with self.time_taken_mgmt_lock:
                    self.time_taken_recent5.append(time_taken)
                    self.time_taken_recent15.append(time_taken)
                    self.time_taken_recent45.append(time_taken)
                    if len(self.time_taken_recent5) > 5:
                        self.time_taken_recent5.remove(self.time_taken_recent5[0])
                    if len(self.time_taken_recent15) > 15:
                        self.time_taken_recent15.remove(self.time_taken_recent15[0])
                    if len(self.time_taken_recent45) > 45:
                        self.time_taken_recent45.remove(self.time_taken_recent45[0])
                    if time_taken > self.max_time_taken_ms:
                        self.max_time_taken_ms = time_taken
                    if len(self.time_taken_recent5) == 5:
                        avg_time_taken_recent5 = sum(self.time_taken_recent5) / len(self.time_taken_recent5)
                    if len(self.time_taken_recent15) == 15:
                        avg_time_taken_recent15 = sum(self.time_taken_recent15) / len(self.time_taken_recent15)
                    if len(self.time_taken_recent45) == 45:
                        avg_time_taken_recent45 = sum(self.time_taken_recent45) / len(self.time_taken_recent45)
                result_str = json.dumps(result)
                self.cache.put_if_not_exist(command_obj["text"], result_str)
                result["time_taken"] = time_taken
                print("DEBUG: Responded to `" + command_obj["text"] + "` with `" + result_str + "` in " + str(time_taken) + "ms")
                conn.sendall(result_str.encode())
        except Exception as ex:
            print("ERROR: The following exception has occurred while handling a connection. (ex: " + str(ex) + ")")
        finally:
            try:
                conn.close()
            except:
                pass
            with self.threads_lock:
                self.threads_count = self.threads_count - 1
                print("DEBUG: Finished a task no " + str(self.tasks_counter) + ". Current threads count: " + str(self.threads_count) + ", time taken (s): " + "{:.2f}".format(time_taken) + ", max time taken (s): " + "{:.2f}".format(self.max_time_taken_ms) + ", time taken averages (5, 15, 45): " + "{:.2f}".format(avg_time_taken_recent5) + " " + "{:.2f}".format(avg_time_taken_recent15) + " " + "{:.2f}".format(avg_time_taken_recent45))

    def check_against_dns_rbls(self, text):
        result = {}
        # TODO: Figure out what's the best output here...
        for dns_rbl in self.dns_rbls_list:
            try:
                print("DEBUG: Checking if item (" + text + ") exists in DNSRBL (" + str(dns_rbl) + ")...")
                self.dns_resolver.query(text + '.' + dns_rbl)
                result[dns_rbl] = True
            except:
                result[dns_rbl] = False

        return result


if __name__ == "__main__":
    args_parser = argparse.ArgumentParser(description="Service for enriching items based on DNSRBLS")
    args_parser.add_argument("--socket-file", required=True,
                             help="The socket file path on which the service will listen", type=str)
    args_parser.add_argument("--max-cache-size", required=True, help="Maximum number of entries to hold in the cache",
                             type=int)

    args = args_parser.parse_args()
    socket_path = os.path.realpath(args.socket_file)

    print("Starting with default parameters... (socket: " + socket_path + ")")
    if os.path.realpath(sys.argv[0]) == socket_path:
        print("ERROR: The socket path refers to the script itself. Something is wrong in the arguments list.")
        args_parser.print_help()
        exit(8)

    while True:
        try:
            server = DnsRblsTesterServer(socket_path=socket_path, max_cache_size=args.max_cache_size)
            server.start()
        except KeyboardInterrupt:
            break
