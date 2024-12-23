# primary libraries
from time import  localtime, strftime
from datetime import datetime
import psutil
import netifaces
import socket
import subprocess

class class_system:
    def __init__(self):
        self.addrs = "127.0.0.1"
        self.mac = "00:00:00:00:00:00"
        self.gws = "127.0.0.1"
    
        # Get the disk usage statistics
        disk_usage = psutil.disk_usage('/')

        # Calculate the total disk space (in bytes)
        self.total_disk_space = disk_usage.total

        # Calculate the used disk space (in bytes)
        self.used_disk_space = disk_usage.used

        # Calculate the free disk space (in bytes)
        self.free_disk_space = disk_usage.free

        # Calculate the percentage of used disk space
        self.disk_usage_percentage = (self.used_disk_space / self.total_disk_space) * 100


    def bytes2human(self, n):
        symbols = (' KB', ' MB', ' GB', ' TB', ' PB', ' E', ' Z', ' Y')
        prefix = {}
        for i, s in enumerate(symbols):
            prefix[s] = 1 << (i+1)*10
        for s in reversed(symbols):
            if n >= prefix[s]:
                value = int(float(n) / prefix[s])
                return '%s%s' % (value, s)
        return "%sB" % n

    def query_sys_ip(self, interface):
        try:
            self.addrs = netifaces.ifaddresses(interface)
        except:
            self.addrs = netifaces.ifaddresses('lo0')

        return self.addrs[netifaces.AF_INET][0]['addr']
    
    def query_sys_disk_total(self):
        roundedGB = round(self.total_disk_space / (1024 * 1024 * 1024))
        return f"{roundedGB} GB"
    
    def query_sys_disk_usage_percent(self):
        return round(self.disk_usage_percentage)

    def query_sys_mac(self):
        self.gws = netifaces.gateways()
        return self.gws['default'][netifaces.AF_INET][0]
    
    def query_sys_cpu_percent(self):
        return round(psutil.cpu_percent(percpu=False,interval=None))

    def query_cpu_count(self):
        return psutil.cpu_count(logical=False)

    def query_sys_memory_usage_percent(self):
        return psutil.virtual_memory().percent

    def query_sys_virtual_memory_total(self):
        total_virtual_memory = psutil.virtual_memory().total
        return f"{round(total_virtual_memory / (1024 * 1024 * 1024))} GB"

    def query_sys_boot_time(self):
        return datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")

    def query_sys_uptime(self):
        uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
        return str(uptime).split('.')[0]
    
    def query_sys_load(self):
        av1, av2, av3 = psutil.getloadavg()
        return "%.1f %.1f %.1f" % (av1, av2, av3)

    def query_sys_interface_io(self, interface):
        return psutil.net_io_counters(pernic=True)[interface]

    def query_sys_hostname(self):
        return socket.gethostname()

    def query_sys_datetime(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def query_sys_serial_number(self):
        try:
            output = subprocess.check_output(["dmidecode", "-s", "system-serial-number"])
            serial_number = output.decode("utf-8").strip()
        except:
            serial_number = "Unknown"
        return serial_number
    
    def query_network_interfaces(self):
        interface_names = [iface for iface in psutil.net_if_addrs().keys() 
                        if iface.startswith(("eth", "en"))]
        return interface_names

    def return_system_resource_usage(self):
        return {
                'sys_hostname': self.query_sys_hostname(),
                'sys_management_ip': self.query_sys_ip('eth0'),
                'sys_uptime': self.query_sys_uptime(),
                'sys_datetime': self.query_sys_datetime(),
                'sys_cpu_usage_percent': self.query_sys_cpu_percent(),
                'sys_memory_usage_percent': self.query_sys_memory_usage_percent(),
                'sys_disk_usage_percent': self.query_sys_disk_usage_percent(),
                'sys_disk_size': self.query_sys_disk_total(),
                'sys_memory_size': self.query_sys_virtual_memory_total(),
                'sys_serial_number': self.query_sys_serial_number()
            }

