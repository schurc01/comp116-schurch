require 'packetfu'
require 'apachelogregex'

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
def nmap_scan?(payload)
    # case insensitive scan for any packet
    # payload containing signature "Nmap..."
    return payload.scan(/Nmap/).length > 0
end

# Checks for nikto scan.
def nikto_scan?(payload)
    # Case insensitive scan for any packet
    # containing "nikto".
    return payload.scan(/Nikto/).length > 0
end

# Checks for credit card number in packet's binary data.
def ccard_leak?(payload)
    # Can only find Visa, Mastercard, American Express
    # and discover for sake of simplicity.
    # Regex credit: www.richardsramblings.com/regex/credit-card-numbers/
    # Note: only find numbers with no spaces/dashes
    cc_regex = "\b(?:3[47]\d|(?:4\d|5[1-5]|65)\d{2}|6011)\d{12}\b"
    return payload.scan(/#{cc_regex}/).length > 0
end

# Checks for a masscan attack.
def masscan?(line)
    # Searches for masscan signature.
    return line.scan(/masscan/).length > 0
end

# Checks for a shellshock attack.
def shellshock?(line)
    # Searches for signature () { :; }
    # with starting characters.
    return line.scan(/\(\)/).length > 0
end

# Checks for anything related to phpMyAdmin.
def phpMyAdmin?(line)
    # Searches for two most common signatures.
    s1 = "phpmyadmin"
    s2 = "pma"
    return line.scan(/#{s1}|#{s2}/).length > 0 
end

# Checks for shellcode injection.
def shellcode?(line)
    # Searches for shellcode of the form \x22\x4d\ etc..
    return line.scan(/(\\x\h\h)+/).length > 0
end

# Function to output alert about incident.
def alert(inc_num, incident, ip, proto, payload)
    puts "#{inc_num}. ALERT #{incident} is detected from #{ip} (#{proto}) (#{payload})!"
end


num_incs = 0
if ARGV[1]
    # Read from web server log.
    
    # Format of the log file.
    format = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
    parser = ApacheLogRegex.new(format)

    File.readlines(ARGV[1]).collect do |line|
        # Parses lines into hashtable to easily split relevant info.
        hash = parser.parse(line)
        
        ip = hash["%h"]
        payload = hash["%{User-Agent}i"]
	
        if nmap_scan?(line)
            alert(num_incs += 1, "NMAP scan", ip,"HTTP", payload)
	elsif nikto_scan?(line)
            alert(num_incs += 1, "NIKTO scan", ip, "HTTP", payload)
        elsif masscan?(line)
            alert(num_incs += 1, "Masscan", ip, "HTTP", payload)
        elsif shellshock?(line)
            alert(num_incs += 1, "Shellshock vulnerability attack", ip, "HTTP", payload)
	elsif phpMyAdmin?(line)
            alert(num_incs += 1, "Someone looking for phpMyAdmin stuff", ip, "HTTP", payload)
        elsif shellcode?(line)
            alert(num_incs += 1, "Shellcode", ip, "HTTP", payload)
        end
    end
else
    # Live Stream
    cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
    cap.stream.each do |p|
        pkt = PacketFu::Packet.parse(p)

        # Only need to worry about TCP Packets.
        if pkt.is_ip? && pkt.is_tcp?
            if null_scan?(pkt)
                alert(num_incs += 1, "NULL scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif fin_scan?(pkt)
                alert(num_incs += 1, "FIN scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif xmas_scan?(pkt)
                alert(num_incs += 1, "XMAS scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif nmap_scan?(pkt.payload)
                alert(num_incs += 1, "NMAP scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
	    elsif nikto_scan?(pkt.payload)
                alert(num_incs += 1, "NIKTO scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
            elsif ccard_leak?(pkt.payload)
                alert(num_incs += 1, "Credit Card Leak", pkt.ip_saddr, pkt.proto.last, pkt.payload)
            end
        end
    end
end
