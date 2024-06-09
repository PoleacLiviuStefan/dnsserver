import socket
from scapy.all import DNS, DNSRR


def get_ip_for_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


domain_name = 'rauter.software'
domain_ip = get_ip_for_domain(domain_name)

if domain_ip is None:
    print(f"Could not resolve IP for {domain_name}")
else:
    print(f"Resolved IP for {domain_name}: {domain_ip}")

    # Creăm un socket UDP
    simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    simple_udp.bind(('0.0.0.0', 53))

    print("DNS server is running...")

    while True:
        request, adresa_sursa = simple_udp.recvfrom(65535)
        # Convertim payload-ul în pachet scapy
        packet = DNS(request)
        dns = packet.getlayer(DNS)
        if dns is not None and dns.opcode == 0:  # DNS QUERY
            print("Received:")
            print(packet.summary())
            # Verificăm dacă interogarea este pentru domeniul specific
            if dns.qd.qname.decode('utf-8') == domain_name + '.':
                dns_answer = DNSRR(
                   rrname=dns.qd.qname,
                   ttl=330,
                   type="A",            
                   rclass="IN",
                   rdata=domain_ip)  # Răspunde cu IP-ul pentru domeniul specific
            else:
                dns_answer = DNSRR(
                   rrname=dns.qd.qname,
                   ttl=330,
                   type="A",            
                   rclass="IN",
                   rdata='0.0.0.0')  # IP-ul default pentru alte interogări

            dns_response = DNS(
                              id = packet[DNS].id,
                              qr = 1,
                              aa = 0,
                              rcode = 0,
                              qd = packet.qd,
                              an = dns_answer)
            print('Sending response:')
            print(dns_response.summary())
            simple_udp.sendto(bytes(dns_response), adresa_sursa)
    simple_udp.close()
