require 'packetfu'
# Incident Alarm
# COMP 116: Security
# By: Susie Church

# Checks for scan where all bits
# are set to 0.
def null_scan?(pkt)
    # all flags must be 0
    return pkt.tcp_flags.to_i == 0
end

# Checks for scan where FIN bit
# is set to 0.
def fin_scan?(pkt)
    # implementation of to_i uses bit shifting
    # to fit all flag vals in an int-- fin flag
    # is the first bit. If fin is set to 1 and
    # tcp_flags.to_i is 1, all other flags must
    # be 0
    return pkt.tcp_flags.fin == 1 && 
           pkt.tcp_flags.to_i == 1
end

# Checks for scan where FIN, PSH, and URG flags
# are set to 1 (according to nmap). 
def xmas_scan?(pkt)
    return pkt.tcp_flags.fin == 1 &&
           pkt.tcp_flags.urg == 1 &&
           pkt.tcp_flags.psh == 1
end

# Checks for nmap scan.
def nmap_scan?(pkt)
    # case insensitive scan for any packet
    # payload containing signature "Nmap..."
    return pkt.payload.scan(/Nmap.../).length > 0
end

# Checks for nikto scan.
def nikto_scan?(pkt)
    # Case insensitive scan for any packet
    # containing "nikto".
    return pkt.payload.scan(/nikto/).length > 0
end

# Checks for credit card number in packet's binary data.
def ccard_leak?(pkt)
    # Can only find Visa, Mastercard, American Express
    # and discover for sake of simplicity.
    # Regex credit: www.richardsramblings.com/regex/credit-card-numbers/
    # Note: only find numbers with no spaces/dashes
    return pkt.payload.scan(/\b(?:3[47]\d|(?:4\d|5[1-5]|65)\d{2}|6011)\d{12}\b/).length > 0
end

# Checks for a masscan attack.
def masscan?(pkt)
end

# Checks for a shellshock attack.
def shellshock?(pkt)
end

# Checks for anything related to phpMyAdmin.
def phpMyAdmin?(pkt)
end

# Checks for shellcode injection.
def shellcode?(pkt)
end

# Function to output alert about incident.
def alert(inc_num, incident, pkt)
puts "#{inc_num}. ALERT #{incident} is detected from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})!"
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
                alert(num_incs += 1, "NULL scan", pkt)
	    elsif fin_scan?(pkt)
                alert(num_incs += 1, "FIN scan", pkt)
	    elsif xmas_scan?(pkt)
                alert(num_incs += 1, "XMAS scan", pkt)
	    elsif nmap_scan?(pkt)
                alert(num_incs += 1, "NMAP scan", pkt)
	    elsif nikto_scan?(pkt)
                alert(num_incs += 1, "NIKTO scan", pkt)
            end
        end
    end
end
