import scapy.all as scapy
from scapy_http import http
from optparse import OptionParser

print("[*] modüller: aktif \a \n")

def listen_packets(interface):
    """
    Belirtilen ağ arayüzü üzerinden paketleri dinler ve analiz eder.
    """
    print(f"[+] {interface} arayüzünde paketler dinleniyor...")
    scapy.sniff(iface=interface, store=False, prn=analyze_packets)


def analyze_packets(packet):
    """
    Gelen ağ paketlerini analiz eder ve gösterir.
    """
    packet.show()

# Optparse kullanarak komut satırı argümanlarını ayarlıyoruz
parser = OptionParser(usage="usage: %prog -i <interface>", version="%prog 1.0")
parser.add_option("-i", "--interface", dest="interface", help="Dinlenecek ağ arayüzünü belirtin (ör. eth0, wlan0)")

(options, args) = parser.parse_args()

# Eğer arayüz belirtilmemişse yardım mesajını göster ve uyarı ver
if not options.interface:
    parser.print_help()
    print("\n[!] Bir ağ arayüzü belirtmelisiniz!")
else:
    # Eğer doğru bir arayüz belirtildiyse paket dinleme işlemi başlar
    listen_packets(options.interface)

