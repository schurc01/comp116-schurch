require 'packetfu'
# Incident Alarm
# COMP 116: Security
# By: Susie Church

# checks for scan where all bits
# are set to 0
def null_scan?(pkt)
    # all flags must be 0
    return pkt.tcp_flags.to_i == 0
end

# checks for scan where FIN bit
# is set to 0
def fin_scan?(pkt)
    # implementation of to_i uses bit shifting
    # to fit all flag vals in an int-- fin flag
    # is the first bit. If fin is set to 1 and
    # tcp_flags.to_i is 1, all other flags must
    # be 0
    return pkt.tcp_flags.fin == 1 && 
           pkt.tcp_flags.to_i == 1
end

# checks for scan where FIN, PSH, and URG flags
# are set to 1 (according to nmap). 
def xmas_scan?(pkt)
    return pkt.tcp_flags.fin == 1 &&
           pkt.tcp_flags.urg == 1 &&
           pkt.tcp_flags.psh == 1
end

# checks for nmap scan
def nmap_scan?(pkt)
    # case sensitive scan for any packet
    # payload containing signature "Nmap..."
    return pkt.payload.scan(/nmap/i).length > 0
end

# checks for nikto scan
def nikto_scan?(pkt)
    # case insensitive scan for any packet
    # containing "nikto"
    return pkt.payload.scan(/nikto/).length > 0
end

def ccard_leak?(pkt)
end

def masscan?(pkt)
end

def shellshock?(pkt)
end

def phpMyAdmin?(pkt)
end

def shellcode?(pkt)
end

def alert(inc_num, incident, source, proto, payload)
puts "#{inc_num}. ALERT #{incident} is detected from #{source} (#{proto}) (#{payload})!"
end

if ARGV[0]
    # Read from web server log
else
    # Live Stream
    num_incs = 0
    cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
    cap.stream.each do |p|
        pkt = PacketFu::Packet.parse(p)
        if pkt.is_ip? && pkt.is_tcp?
            if null_scan?(pkt)
                alert(num_incs += 1, "NULL scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif fin_scan?(pkt)
                alert(num_incs += 1, "FIN scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif xmas_scan?(pkt)
                alert(num_incs += 1, "XMAS scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif nmap_scan?(pkt)
                alert(num_incs += 1, "NMAP scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif nikto_scan?(pkt)
                alert(num_incs += 1, "NIKTO scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
            end
        end
    end
end
