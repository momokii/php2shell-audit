<?php declare(strict_types=1);

$socket = @fsockopen('127.0.0.1', 80, $errorCode, $errorMessage, 2);
if ($socket === false) {
    fwrite(STDERR, "Apache readiness connection failed\n");
    exit(1);
}

stream_set_timeout($socket, 2);
if (fwrite($socket, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n") === false) {
    fclose($socket);
    fwrite(STDERR, "Apache readiness request failed\n");
    exit(1);
}

$statusLine = fgets($socket);
fclose($socket);
if ($statusLine === false || !str_contains($statusLine, '200')) {
    fwrite(STDERR, "Apache readiness did not return HTTP 200\n");
    exit(1);
}

exit(0);
