import nmap
import pandas as pd


class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    # 192.168.1.0/24 represents the IP address range from 192.168.1.0 to 192.168.1.255
    def scan_network(self, network_mask='192.168.1.0/24'):
        """
        Scan network and return a DataFrame with IP addresses and other relevant details.
        """
        print("Scanning Network")
        self.nm.scan(hosts=network_mask, arguments='-sn')
        print("Scanning Complete")

        data = {'ip': [], 'mac': [], 'name': []}
        for host_ip in self.nm.all_hosts():
            host_mac = self.nm[host_ip]['addresses'].get('mac', '')
            host_name = self.nm[host_ip].hostname()
            data['ip'].append(host_ip)
            data['mac'].append(host_mac)
            data['name'].append(host_name)

        return pd.DataFrame(data)

    def deep_scan(self, ip_list):
        """
        Deep Scan each IP address in the given list to find open ports.
        Return a DataFrame with IP addresses and status of specified ports.
        """
        print("Deep Scanning Devices")
        PORTS = ['20', '21', '23', '53', '80', '137', '139', '2323', '22', '25', '43', '445', '8080', '8443', '1433',
                 '1434', '3306', '3389']
        data = {
            'ip': [],
            'port20': [], 'port21': [], 'port23': [], 'port53': [],
            'port80': [], 'port137': [], 'port139': [], 'port2323': [],
            'port22': [], 'port25': [], 'port43': [], 'port445': [],
            'port8080': [], 'port8443': [], 'port1433': [], 'port1434': [],
            'port3306': [], 'port3389': []
        }



        for ip in ip_list:
            self.nm.scan(ip, arguments='-p ' + ','.join(PORTS))
            data['ip'].append(ip)

            for port in PORTS:
                # Retrieve the status of the specified TCP port for the given IP; default to 'closed' if not found.
                port_status = self.nm[ip]['tcp'].get(int(port), {}).get('state', 'closed')
                data[f'port{port}'].append(port_status)

        print("Deep Scanning Complete")
        return pd.DataFrame(data)


# Example Usage:
scanner = NetworkScanner()
network_data = scanner.scan_network('192.168.1.0/24')  #192.168.1.0/24 represents the IP address range from 192.168.1.0 to 192.168.1.255
print(network_data)

# Deep scanning
deep_scan_data = scanner.deep_scan(network_data['ip'].tolist())
print(deep_scan_data)
