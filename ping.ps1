$subnet = "192.168"

for ($i=1;$i -lt 3; $i++) {
    for ($j=240;$j -lt 256; $j++) {
    $ip = "$subnet.$i.$j"
    $pingResult = Test-Connection -ComputerName $ip -Count 1 -Quiet -erroraction SilentlyContinue
    if ($pingResult) {
        Write-Host "$ip is online"
        $ip | out-file -FilePath C:\Users\matth\Downloads\foundIPs.txt
    } else {
        write-host "$ip is XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    }
  }
}