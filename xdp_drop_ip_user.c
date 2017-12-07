/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "bpf_load.h"
#include "libbpf.h"
#include <readline/readline.h>
#include <stdbool.h>

static int set_link_xdp_fd(int ifindex, int fd)
{
	struct sockaddr_nl sa;
	int sock, seq = 0, len, ret = -1;
	char buf[4096];
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | 43/*IFLA_XDP*/;

	nla_xdp = (struct nlattr *)((char *)nla + NLA_HDRLEN);
	nla_xdp->nla_type = 1/*IFLA_XDP_FD*/;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len = NLA_HDRLEN + nla_xdp->nla_len;

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		printf("recv from netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
	     nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_pid != getpid()) {
			printf("Wrong pid %d, expected %d\n",
			       nh->nlmsg_pid, getpid());
			goto cleanup;
		}
		if (nh->nlmsg_seq != seq) {
			printf("Wrong seq %d, expected %d\n",
			       nh->nlmsg_seq, seq);
			goto cleanup;
		}
		switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
			err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (!err->error)
				continue;
			printf("nlmsg error %s\n", strerror(-err->error));
			goto cleanup;
		case NLMSG_DONE:
			break;
		}
	}

	ret = 0;

cleanup:
	close(sock);
	return ret;
}

static int ifindex;

static void int_exit(int sig)
{
	set_link_xdp_fd(ifindex, -1);
	exit(0);
}

static void get_ip(struct in_addr *ip, bool *remove)
{
	static const char *prompt = "Type an ip addres to block.  Start with - to unblock: ";
	char *line = readline(prompt);
	char *ip_str;
	if (line == NULL) {
		printf("NULL, return\n");
		return; 
	}
	if (strlen(line) < 4) {
		printf("too short\n");
		free(line);
		return;
	}
	ip_str = line;
	*remove = false;
	if (line[0] == '-') {
		*remove = true;
		ip_str++;
	}
	/* return value ignored for now */
	if (inet_pton(AF_INET, ip_str, ip) != 1)
		ip->s_addr = 0;
	free(line);
	return;
}

static void drop_ips(void)
{
	int rc;
	printf("Reading from stdin\n");
	while (1) {
		struct in_addr ip;
		bool remove = true;
		get_ip(&ip, &remove);
		if (!ip.s_addr)
			continue;
		if (remove) {
			rc = bpf_delete_elem(map_fd[0], &ip.s_addr);
			if (rc)
				printf("Delete elem failed: %d\n", rc);
		} else {
			uint32_t value = 1;
			rc = bpf_update_elem(map_fd[0], &ip.s_addr, &value, BPF_ANY);
			if (rc)
				printf("update elem failed: %d\n", rc);
		}
	}
}

int main(int ac, char **argv)
{
	/* not const because called functions don't use const */
	char *ifname;
	char *filename;

	if (ac != 3) {
		printf("usage: %s IFNAME FILE\n", argv[0]);
		return 1;
	}
	ifname = argv[1];
	filename = argv[2];
	
	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		printf("ifname %s not found\n", ifname);
		return 1;
	}

	if (load_bpf_file(filename)) {
		printf("load_bpf_file(%s) failed: %s\n", filename, bpf_log_buf);
		return 1;
	}

	if (!prog_fd[0]) {
		printf("load_bpf_file(%s) error: %s\n", filename, strerror(errno));
		return 1;
	}

	signal(SIGINT, int_exit);

	if (set_link_xdp_fd(ifindex, prog_fd[0]) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

	drop_ips();
	return 0;
}

