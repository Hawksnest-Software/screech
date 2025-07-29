#!/usr/sbin/dtrace -s

/*
 * screech_dtrace.d - Network connection monitoring using DTrace
 * This provides kernel-level monitoring on macOS without requiring Endpoint Security
 * Note: Requires running with sudo
 */

#pragma D option quiet
#pragma D option switchrate=10

dtrace:::BEGIN
{
    printf("Starting screech DTrace network monitor...\n");
    printf("Monitoring network connections at kernel level\n");
    printf("Press Ctrl+C to stop\n\n");
    printf("%-20s %-8s %-8s %-22s %-22s %-16s %s\n", 
           "TIMESTAMP", "PID", "UID", "SOURCE", "DESTINATION", "PROCESS", "PATH");
}

/* Track TCP connections */
tcp:::connect-request
{
    this->timestamp = strftime("%Y-%m-%d %H:%M:%S", walltimestamp);
    this->src = strjoin(strjoin(inet_ntoa(&args[2]->ip_src), ":"), 
                        lltostr(args[4]->tcp_sport));
    this->dst = strjoin(strjoin(inet_ntoa(&args[2]->ip_dst), ":"), 
                        lltostr(args[4]->tcp_dport));
    
    printf("%-20s %-8d %-8d %-22s %-22s %-16s %s\n",
           this->timestamp,
           pid,
           uid,
           this->src,
           this->dst,
           execname,
           curpsinfo->pr_psargs);
}

/* Track UDP send operations */
udp:::send
{
    this->timestamp = strftime("%Y-%m-%d %H:%M:%S", walltimestamp);
    this->src = strjoin(strjoin(inet_ntoa(&args[2]->ip_src), ":"), 
                        lltostr(args[4]->udp_sport));
    this->dst = strjoin(strjoin(inet_ntoa(&args[2]->ip_dst), ":"), 
                        lltostr(args[4]->udp_dport));
    
    printf("%-20s %-8d %-8d %-22s %-22s %-16s %s\n",
           this->timestamp,
           pid,
           uid,
           this->src,
           this->dst,
           execname,
           curpsinfo->pr_psargs);
}

/* Track socket system calls for additional context */
syscall::socket:entry
/args[0] == 2 || args[0] == 30/ /* AF_INET or AF_INET6 */
{
    this->socket_domain = args[0];
    this->socket_type = args[1];
    this->socket_protocol = args[2];
}

syscall::socket:return
/this->socket_domain/
{
    this->timestamp = strftime("%Y-%m-%d %H:%M:%S", walltimestamp);
    this->protocol = (this->socket_type == 1) ? "TCP" : 
                     (this->socket_type == 2) ? "UDP" : "OTHER";
    
    printf("%-20s %-8d %-8d %-22s %-22s %-16s SOCKET_CREATE:%s\n",
           this->timestamp,
           pid,
           uid,
           "local",
           "unknown",
           execname,
           this->protocol);
    
    this->socket_domain = 0;
    this->socket_type = 0;
    this->socket_protocol = 0;
}

/* Track connect system calls */
syscall::connect:entry
{
    this->connect_fd = args[0];
    this->sockaddr = (struct sockaddr *)copyin(args[1], args[2]);
}

syscall::connect:return
/this->sockaddr && this->sockaddr->sa_family == 2/ /* AF_INET */
{
    this->timestamp = strftime("%Y-%m-%d %H:%M:%S", walltimestamp);
    this->sin = (struct sockaddr_in *)this->sockaddr;
    this->dst_ip = inet_ntoa((ipaddr_t *)&this->sin->sin_addr);
    this->dst_port = ntohs(this->sin->sin_port);
    
    printf("%-20s %-8d %-8d %-22s %-22s %-16s CONNECT_ATTEMPT\n",
           this->timestamp,
           pid,
           uid,
           "local",
           strjoin(this->dst_ip, strjoin(":", lltostr(this->dst_port))),
           execname);
    
    this->connect_fd = 0;
    this->sockaddr = 0;
}

/* Clean up variables */
tcp:::connect-request,
udp:::send
{
    this->timestamp = 0;
    this->src = 0;
    this->dst = 0;
}

/* Handle Ctrl+C gracefully */
dtrace:::END
{
    printf("\nStopping screech DTrace monitor\n");
}
