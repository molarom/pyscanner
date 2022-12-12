#!/usr/bin/env python3

import os
import time
import re
import sys

from multiprocessing import Process

# Import GTK libraries for Notifications.
import gi
gi.require_version('Notify', '0.7')
from gi.repository import Notify

# Initialize libnotify
Notify.init("pyscanner.py")

def parse_output(scan_file):
    f = open(scan_file, 'r')
    lines = f.read()

    # Get all open ports.
    pattern = re.compile(r"\d{1,5}\/open")
    matches = re.findall(pattern, lines)

    f.close()

    # Strip "/open" from elements in list.
    stripped = [s.strip('/open') for s in matches]

    # Join elements to create a single string.
    ports = ','.join(stripped)

    return ports

def top_100_scan(cwd, ip, body, extra_opts):
    # For the system alert.
    header = "Top 100 scan"
    output_file = "".join([cwd, "/scans/top_100.gnmap"])

    nmap_scan = "nmap " + extra_opts + " -F " + ip + " -oG " + output_file

    print(nmap_scan)
    os.system(nmap_scan)

    print("Results saved to " + output_file)

    # Generate our alert.
    notification = Notify.Notification.new(
        header,
        body,
    )

    # Display our alert.
    notification.show()

def all_ports_scan(cwd, ip, body, extra_opts):
    header = "Scan of all ports."
    output_file = "".join([cwd, "/scans/all_ports.gnmap"])

    nmap_scan = "nmap " + extra_opts +  " -p- " + ip + " -oG " + output_file

    print(nmap_scan)
    os.system(nmap_scan)

    notification = Notify.Notification.new(
        header,
        body,
    )

    notification.show()

def script_scan(cwd, ip, body, extra_opts):
    header = "Script scan"
    output_file = "".join([cwd, "/scans/script_scan.gnmap"])

    # Parse file to retrieve open ports as string.
    ports = parse_output("".join([cwd, "/scans/all_ports.gnmap"]))

    nmap_scan = "nmap -sC " + extra_opts + " -p " + ports + " " + ip + " -oN " + output_file

    print(nmap_scan)
    os.system(nmap_scan)

def http_title_scan(cwd, ip, body, extra_opts):
    header = "HTTP Title Scan"
    output_file = "".join([cwd, "/scans/http_scan.nmap"])

    ports = parse_output("".join([cwd, "/scans/all_ports.gnmap"]))

    nmap_scan = "nmap " + extra_opts + " --script='http-title'" +  " -p " + ports + " " + ip + " -oN " + output_file

    print(nmap_scan)
    os.system(nmap_scan)

    notification = Notify.Notification.new(
        header,
        body,
    )

    notification.show()

def directory_chk(cur_dir):
    scan_dir = cur_dir.strip()
    scan_dir += "/scans/"
    exists = os.path.exists(scan_dir)

    print("Checking if scans directory exits...")
    if exists:
        print("./scans exists, commencing scans now.")
    else:
        print("./scans does not exist, creating then scanning.")
        os.mkdir(scan_dir)

    return True

if __name__ == "__main__":

    # Check for root to run stealth scans.
    if not os.geteuid() == 0:
        sys.exit('This script must be run as root.')

    if len(sys.argv) < 2:
        os.error("[-] Usage: pyscan <ip> <extra_flags>")

    # Arguments passed to functions.
    ip = sys.argv[1]
    extra_opts = sys.argv[2]
    cwd = os.getcwd()

    # Body for the system notification."
    body = "Scan of " + ip + " has finished!"

    # List for processes.
    procs = []

    if directory_chk(cwd):
        p1 = Process(target=top_100_scan, args=(cwd,ip,body,extra_opts,))
        p2 = Process(target=all_ports_scan, args=(cwd,ip,body,extra_opts,))
        p3 = Process(target=script_scan, args=(cwd,ip,body,extra_opts,))
        p4 = Process(target=http_title_scan, args=(cwd,ip,body,extra_opts,))
        procs.extend([p1, p2, p3, p4])

        for proc in procs:
            proc.start()
            proc.join()

        # Script scan need to wait for all ports to finish.

    # Cleanup GTK.
    Notify.uninit()
