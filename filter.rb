module SuspiciousPatterns

  XSS_PATTERNS = {
      "html open tag" => "<",
      "html close tag" => ">",
      "[ - possible js" => /\[|\]/,
      "~ character" => "~",
      "grave accent !" => "`",
  }
  EVADING_PATTERNS = {
      "utf7/8 encoding" => "&#",
      "M$ encoding" => "%U",
  }
  DIR_TRAVERSAL_PATTERNS = {
      "double dot" => /\.\./,
      "passwd file" => "etc/passwd",
      "obvious windows path" => /c:\\\\/,
      "obvious probe" => "cmd.exe",
      "backslash" => /\\/,
  }
  SQL_PATTERNS = {
      "sql keywords"  => /select|union|update|delete|insert|table|from|ascii|hex|unhex|drop/,
      "double quote" => /"/,
      "possible hex encoding" => "0x",
      "mysql comment opening" => /\/\*/,
      "mysql comment ending"  => /\*\//,
      "mysql keyword - pipe" => /\|/,
      "mysql keyword - and" => "&&",
      "mysql comment " => "--",
      "; " => ";",
      "parenthesis, probable sql/xss" => /\(|\)/,
      "simple quote" => "'",
  }

  FILE_UPLOAD_PATTERNS = {} #regex for common file exension?

  ALL_PATTERNS = [XSS_PATTERNS, EVADING_PATTERNS,DIR_TRAVERSAL_PATTERNS, SQL_PATTERNS, FILE_UPLOAD_PATTERNS ]

end



class Filter
  include SuspiciousPatterns

  attr_accessor :lines_analyzed
  attr_accessor :issues_detected

  def initialize
    self.lines_analyzed=0
    self.issues_detected=0
  end


  def filter(event)

    suspicious_entries = SuspiciousPatterns::ALL_PATTERNS.map { | patterns |
      patterns.select { | _ , pattern | event.uri.to_s.match(pattern) }.map  { |key, value| [key, value]}
    }.flatten(1)

    if suspicious_entries.any?
      notify(event, suspicious_entries)
      self.issues_detected += 1
    end

  end

  def notify(event, suspicious_entries)
    arr= suspicious_entries.flatten
    puts "[WARNING] Detected suspicious pattern in following URI:  #{event.uri}"
    puts "\t  Patterns matching: " + arr.values_at(* arr.each_index.select {|i| i.even?}).join(", ")
    puts "\t  PaperTrail log entry id: #{event.id}"
    puts "\t  Date reported: #{event.date}"
    puts "\t  Full log entry: "
    puts "\t  " + event.full_line
  end

end

class PaperTrailLogEntry
  attr_accessor :full_line
  attr_accessor :id
  attr_accessor :date
  attr_accessor :uri

  def initialize(paper_trail_log_line)
    self.full_line= paper_trail_log_line.to_s
    self.id= paper_trail_log_line.split[0]
    self.date= paper_trail_log_line.split[1]
    uri = paper_trail_log_line.match(/path=".*"/).to_s.split
    self.uri = uri[0].to_s.tr!("path=","").to_s[1..-2]
  end

end

filter = Filter.new

ARGF.each do | line |
  paper_trail_log_entry = PaperTrailLogEntry.new(line)
  filter.filter(paper_trail_log_entry)
  filter.lines_analyzed += 1
end

puts "-> Total events parsed:  #{filter.lines_analyzed}"

if filter.issues_detected != 0
  puts "-> Total issues detected: #{filter.issues_detected}"
else
  puts "-> No issues detected"
end

