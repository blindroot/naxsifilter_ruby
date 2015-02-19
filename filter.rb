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
#      "double quote" => /"/,
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
      patterns.select { | _ , pattern | event.match(pattern) }.map  { |key, value| [key, value]}
    }.flatten(1)

    if suspicious_entries.any?
      notify(event)
      self.issues_detected += 1
    end

  end

  def notify(event)
    puts "[WARNING]  Detected suspicious pattern in:  #{event}"
  end

end

filter = Filter.new

ARGF.each do | line |
  filter.filter(line)
  filter.lines_analyzed += 1
end

puts "-> Total events parsed:  #{filter.lines_analyzed}"

if filter.issues_detected != 0
  puts "-> Total issues detected: #{filter.issues_detected}"
  exit 2
else
  puts "-> No issues detected"
end

