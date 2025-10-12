Host host_a
    HostName 127.0.0.1
    Port 2222

Host host_b
    HostName 127.0.0.1
    Port 2223

Host host_c
    HostName 127.0.0.1
    Port 2224

Host *
    StrictHostKeyChecking yes
    ForwardAgent yes