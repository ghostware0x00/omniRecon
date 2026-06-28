response = "['HTTP/1.1 301 Moved Permanently', 'Date: Sat, 27 Jun 2026 17:08:14 GMT', 'Content-Type: text/html; charset=UTF-8', 'Transfer-Encoding: chunked', 'Connection: keep-alive', 'Server-Timing: cfEdge;dur=9,cfOrigin;dur=0', 'Location: https://www.yougetsignal.com/', 'Server: cloudflare', 'CF-RAY: a1260d746ae77fa8-BLR', '', '299', '<html>',"

print(response)

print("<------------------------------------->")

print(response.split("\r\n"))