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


  def filter(event, paper_trail_metadata)

    suspicious_entries = SuspiciousPatterns::ALL_PATTERNS.map { | patterns |
      patterns.select { | _ , pattern | event.to_s.match(pattern) }.map  { |key, value| [key, value]}
    }.flatten(1)

    if suspicious_entries.any?
      notify(event, paper_trail_metadata)
      self.issues_detected += 1
    end

  end

  def notify(event, paper_trail_metadata)
    puts "[WARNING] Detected suspicious pattern in following URI:  #{event}"
    puts "\t  PaperTrail log entry id: #{paper_trail_metadata["logentry_id"]}"
    puts "\t  Date reported: #{paper_trail_metadata["logentry_date"]}"
  end

end



filter = Filter.new

ARGF.each do | line |
  paper_trail_metadata = { "logentry_id" => line.split[0], "logentry_date" => line.split[1]}
  uri_to_examine = line.match(/path=".*"/).to_s.split
  uri_to_examine = uri_to_examine[0].to_s.tr!("path=\"","")

  filter.filter(uri_to_examine, paper_trail_metadata)
  filter.lines_analyzed += 1
end

puts "-> Total events parsed:  #{filter.lines_analyzed}"

if filter.issues_detected != 0
  puts "-> Total issues detected: #{filter.issues_detected}"
else
  puts "-> No issues detected"
end

