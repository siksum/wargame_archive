#!/usr/bin/perl
use Socket;
$port = 5110;
@exec = ("./vuln");
socket(SERVER, PF_INET, SOCK_STREAM, 6) or die "Socket creation failed: $!";
setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die "Set socket option failed: $!";
bind(SERVER, sockaddr_in($port, INADDR_ANY)) or die "Bind failed: $!";
listen(SERVER, SOMAXCONN) or die "Listen failed: $!";
$SIG{"CHLD"} = "IGNORE";
while($addr = accept CLIENT, SERVER){
    $| = 1;
    ($port, $packed_ip) = sockaddr_in($addr); 
    $datestring = localtime();
    $ip = inet_ntoa($packed_ip);
    print "$ip: $port connected($datestring)\n";
    fork || do {
        $| = 1;
        close SERVER;
        open STDIN,  "<&CLIENT" or die "Redirect STDIN failed: $!";
        open STDOUT, ">&CLIENT" or die "Redirect STDOUT failed: $!";
        open STDERR, ">&CLIENT" or die "Redirect STDERR failed: $!";
        close CLIENT;
        exec @exec or die "Exec failed: $!";
        exit 0;
    };
    close CLIENT;
}
close SERVER;