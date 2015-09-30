require 'packetfu'
# Incident Alarm
# COMP 116: Security
# By: Susie Church

def null_scan?(pkt)
    # all flags must be 0
    return pkt.tcp_flags.to_i == 0
end

def fin_scan?(pkt)
    # implementation of to_i uses bit shifting
    # to fit all flag vals in an int-- fin flag
    # is the first bit. If fin is set to 1 and
    # tcp_flags.to_i is 1, all other flags must
    # be 0
    return (pkt.tcp_flags.fin == 1) && 
           (pkt.tcp_flags.to_i == 1)
end

def xmas_scan?(pkt)
    # all flags (6 bits) are set to 1
    return pkt.tcp_flags.to_i == 31
end

def nmap_scan?(pkt)
    return pkt.payload.include?("Nmap")
end

def nikto_scan?(pkt)
    return pkt.payload.include?("Nikto")
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

# Live Stream
num_incs = 0
cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
cap.stream.each do |p|
    pkt = PacketFu::Packet.parse(p)
    if pkt.is_ip? && pkt.is_tcp?
        if null_scan?(pkt)
            alert(++num_incs, "NULL scan", pkt.ip_saddr, pkt.ip_proto, pkt.payload)
	elsif fin_scan?(pkt)
            alert(++num_incs, "FIN scan", pkt.ip_saddr, pkt.ip_proto, pkt.payload)
	elsif xmas_scan?(pkt)
            alert(++num_incs, "XMAS scan", pkt.ip_saddr, pkt.ip_proto, pkt.payload)
	elsif nmap_scan?(pkt)
            alert(++num_incs, "NMAP scan", pkt.ip_saddr, pkt.ip_proto, pkt.payload)
	else # nikto_scan?(pkt)
            alert(++num_incs, "NIKTO scan", pkt.ip_saddr, pkt.ip_proto, pkt.payload)
        end
    end
end
