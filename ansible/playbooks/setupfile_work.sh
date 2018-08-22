node1 | SUCCESS => {
    "ansible_facts": {
        "ansible_all_ipv4_addresses": [
            "10.142.0.6"
        ], 
        "ansible_all_ipv6_addresses": [
            "fe80::4001:aff:fe8e:6"
        ], 
        "ansible_apparmor": {
            "status": "disabled"
        }, 
        "ansible_architecture": "x86_64", 
        "ansible_bios_date": "01/01/2011", 
        "ansible_bios_version": "Google", 
        "ansible_cmdline": {
            "BOOT_IMAGE": "/boot/vmlinuz-3.10.0-862.6.3.el7.x86_64", 
            "console": "ttyS0,38400n8", 
            "crashkernel": "auto", 
            "ro": true, 
            "root": "UUID=823db525-82d9-467e-acdf-7379cbd85171"
        }, 
        "ansible_date_time": {
            "date": "2018-08-18", 
            "day": "18", 
            "epoch": "1534554725", 
            "hour": "01", 
            "iso8601": "2018-08-18T01:12:05Z", 
            "iso8601_basic": "20180818T011205393954", 
            "iso8601_basic_short": "20180818T011205", 
            "iso8601_micro": "2018-08-18T01:12:05.394036Z", 
            "minute": "12", 
            "month": "08", 
            "second": "05", 
            "time": "01:12:05", 
            "tz": "UTC", 
            "tz_offset": "+0000", 
            "weekday": "Saturday", 
            "weekday_number": "6", 
            "weeknumber": "33", 
            "year": "2018"
        }, 
        "ansible_default_ipv4": {
            "address": "10.142.0.6", 
            "alias": "eth0", 
            "broadcast": "10.142.0.6", 
            "gateway": "10.142.0.1", 
            "interface": "eth0", 
            "macaddress": "42:01:0a:8e:00:06", 
            "mtu": 1460, 
            "netmask": "255.255.255.255", 
            "network": "10.142.0.6", 
            "type": "ether"
        }, 
        "ansible_default_ipv6": {}, 
        "ansible_device_links": {
            "ids": {
                "sda": [
                    "google-node1", 
                    "scsi-0Google_PersistentDisk_node1"
                ], 
                "sda1": [
                    "google-node1-part1", 
                    "scsi-0Google_PersistentDisk_node1-part1"
                ]
            }, 
            "labels": {
                "sda1": [
                    "\\x2f"
                ]
            }, 
            "masters": {}, 
            "uuids": {
                "sda1": [
                    "823db525-82d9-467e-acdf-7379cbd85171"
                ]
            }
        }, 
        "ansible_devices": {
            "sda": {
                "holders": [], 
                "host": "Non-VGA unclassified device: Red Hat, Inc. Virtio SCSI", 
                "links": {
                    "ids": [
                        "google-node1", 
                        "scsi-0Google_PersistentDisk_node1"
                    ], 
                    "labels": [], 
                    "masters": [], 
                    "uuids": []
                }, 
                "model": "PersistentDisk", 
                "partitions": {
                    "sda1": {
                        "holders": [], 
                        "links": {
                            "ids": [
                                "google-node1-part1", 
                                "scsi-0Google_PersistentDisk_node1-part1"
                            ], 
                            "labels": [
                                "\\x2f"
                            ], 
                            "masters": [], 
                            "uuids": [
                                "823db525-82d9-467e-acdf-7379cbd85171"
                            ]
                        }, 
                        "sectors": "20969472", 
                        "sectorsize": 512, 
                        "size": "10.00 GB", 
                        "start": "2048", 
                        "uuid": "823db525-82d9-467e-acdf-7379cbd85171"
                    }
                }, 
                "removable": "0", 
                "rotational": "1", 
                "sas_address": null, 
                "sas_device_handle": null, 
                "scheduler_mode": "deadline", 
                "sectors": "20971520", 
                "sectorsize": "512", 
                "size": "10.00 GB", 
                "support_discard": "512", 
                "vendor": "Google", 
                "virtual": 1
            }
        }, 
        "ansible_distribution": "CentOS", 
        "ansible_distribution_file_parsed": true, 
        "ansible_distribution_file_path": "/etc/redhat-release", 
        "ansible_distribution_file_variety": "RedHat", 
        "ansible_distribution_major_version": "7", 
        "ansible_distribution_release": "Core", 
        "ansible_distribution_version": "7.5.1804", 
        "ansible_dns": {
            "nameservers": [
                "169.254.169.254"
            ], 
            "search": [
                "c.my-project-second-211910.internal", 
                "google.internal"
            ]
        }, 
        "ansible_domain": "c.my-project-second-211910.internal", 
        "ansible_effective_group_id": 1001, 
        "ansible_effective_user_id": 1000, 
        "ansible_env": {
            "HOME": "/home/ec2-user", 
            "LANG": "en_US.utf-8", 
            "LC_ALL": "en_US.utf-8", 
            "LESSOPEN": "||/usr/bin/lesspipe.sh %s", 
            "LOGNAME": "ec2-user", 
            "LS_COLORS": "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=01;05;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=01;36:*.au=01;36:*.flac=01;36:*.mid=01;36:*.midi=01;36:*.mka=01;36:*.mp3=01;36:*.mpc=01;36:*.ogg=01;36:*.ra=01;36:*.wav=01;36:*.axa=01;36:*.oga=01;36:*.spx=01;36:*.xspf=01;36:", 
            "MAIL": "/var/mail/ec2-user", 
            "PATH": "/usr/local/bin:/usr/bin", 
            "PWD": "/home/ec2-user", 
            "SHELL": "/bin/bash", 
            "SHLVL": "2", 
            "SSH_CLIENT": "10.142.0.3 40138 22", 
            "SSH_CONNECTION": "10.142.0.3 40138 10.142.0.6 22", 
            "SSH_TTY": "/dev/pts/1", 
            "TERM": "xterm", 
            "USER": "ec2-user", 
            "XDG_RUNTIME_DIR": "/run/user/1000", 
            "XDG_SESSION_ID": "14", 
            "_": "/usr/bin/python"
        }, 
        "ansible_eth0": {
            "active": true, 
            "device": "eth0", 
            "features": {
                "busy_poll": "off [fixed]", 
                "fcoe_mtu": "off [fixed]", 
                "generic_receive_offload": "on", 
                "generic_segmentation_offload": "on", 
                "highdma": "on [fixed]", 
                "hw_tc_offload": "off [fixed]", 
                "l2_fwd_offload": "off [fixed]", 
                "large_receive_offload": "off [fixed]", 
                "loopback": "off [fixed]", 
                "netns_local": "off [fixed]", 
                "ntuple_filters": "off [fixed]", 
                "receive_hashing": "off [fixed]", 
                "rx_all": "off [fixed]", 
                "rx_checksumming": "on [fixed]", 
                "rx_fcs": "off [fixed]", 
                "rx_udp_tunnel_port_offload": "off [fixed]", 
                "rx_vlan_filter": "off [fixed]", 
                "rx_vlan_offload": "off [fixed]", 
                "rx_vlan_stag_filter": "off [fixed]", 
                "rx_vlan_stag_hw_parse": "off [fixed]", 
                "scatter_gather": "on", 
                "tcp_segmentation_offload": "on", 
                "tx_checksum_fcoe_crc": "off [fixed]", 
                "tx_checksum_ip_generic": "on", 
                "tx_checksum_ipv4": "off [fixed]", 
                "tx_checksum_ipv6": "off [fixed]", 
                "tx_checksum_sctp": "off [fixed]", 
                "tx_checksumming": "on", 
                "tx_fcoe_segmentation": "off [fixed]", 
                "tx_gre_csum_segmentation": "off [fixed]", 
                "tx_gre_segmentation": "off [fixed]", 
                "tx_gso_partial": "off [fixed]", 
                "tx_gso_robust": "off [fixed]", 
                "tx_ipip_segmentation": "off [fixed]", 
                "tx_lockless": "off [fixed]", 
                "tx_nocache_copy": "off", 
                "tx_scatter_gather": "on", 
                "tx_scatter_gather_fraglist": "off [fixed]", 
                "tx_sctp_segmentation": "off [fixed]", 
                "tx_sit_segmentation": "off [fixed]", 
                "tx_tcp6_segmentation": "on", 
                "tx_tcp_ecn_segmentation": "off [fixed]", 
                "tx_tcp_mangleid_segmentation": "off", 
                "tx_tcp_segmentation": "on", 
                "tx_udp_tnl_csum_segmentation": "off [fixed]", 
                "tx_udp_tnl_segmentation": "off [fixed]", 
                "tx_vlan_offload": "off [fixed]", 
                "tx_vlan_stag_hw_insert": "off [fixed]", 
                "udp_fragmentation_offload": "off [fixed]", 
                "vlan_challenged": "off [fixed]"
            }, 
            "hw_timestamp_filters": [], 
            "ipv4": {
                "address": "10.142.0.6", 
                "broadcast": "10.142.0.6", 
                "netmask": "255.255.255.255", 
                "network": "10.142.0.6"
            }, 
            "ipv6": [
                {
                    "address": "fe80::4001:aff:fe8e:6", 
                    "prefix": "64", 
                    "scope": "link"
                }
            ], 
            "macaddress": "42:01:0a:8e:00:06", 
            "module": "virtio_net", 
            "mtu": 1460, 
            "pciid": "virtio1", 
            "promisc": false, 
            "timestamping": [
                "rx_software", 
                "software"
            ], 
            "type": "ether"
        }, 
        "ansible_fips": false, 
        "ansible_form_factor": "Other", 
        "ansible_fqdn": "node1.c.my-project-second-211910.internal", 
        "ansible_hostname": "node1", 
        "ansible_interfaces": [
            "lo", 
            "eth0"
        ], 
        "ansible_is_chroot": true, 
        "ansible_iscsi_iqn": "", 
        "ansible_kernel": "3.10.0-862.6.3.el7.x86_64", 
        "ansible_lo": {
            "active": true, 
            "device": "lo", 
            "features": {
                "busy_poll": "off [fixed]", 
                "fcoe_mtu": "off [fixed]", 
                "generic_receive_offload": "on", 
                "generic_segmentation_offload": "on", 
                "highdma": "on [fixed]", 
                "hw_tc_offload": "off [fixed]", 
                "l2_fwd_offload": "off [fixed]", 
                "large_receive_offload": "off [fixed]", 
                "loopback": "on [fixed]", 
                "netns_local": "on [fixed]", 
                "ntuple_filters": "off [fixed]", 
                "receive_hashing": "off [fixed]", 
                "rx_all": "off [fixed]", 
                "rx_checksumming": "on [fixed]", 
                "rx_fcs": "off [fixed]", 
                "rx_udp_tunnel_port_offload": "off [fixed]", 
                "rx_vlan_filter": "off [fixed]", 
                "rx_vlan_offload": "off [fixed]", 
                "rx_vlan_stag_filter": "off [fixed]", 
                "rx_vlan_stag_hw_parse": "off [fixed]", 
                "scatter_gather": "on", 
                "tcp_segmentation_offload": "on", 
                "tx_checksum_fcoe_crc": "off [fixed]", 
                "tx_checksum_ip_generic": "on [fixed]", 
                "tx_checksum_ipv4": "off [fixed]", 
                "tx_checksum_ipv6": "off [fixed]", 
                "tx_checksum_sctp": "on [fixed]", 
                "tx_checksumming": "on", 
                "tx_fcoe_segmentation": "off [fixed]", 
                "tx_gre_csum_segmentation": "off [fixed]", 
                "tx_gre_segmentation": "off [fixed]", 
                "tx_gso_partial": "off [fixed]", 
                "tx_gso_robust": "off [fixed]", 
                "tx_ipip_segmentation": "off [fixed]", 
                "tx_lockless": "on [fixed]", 
                "tx_nocache_copy": "off [fixed]", 
                "tx_scatter_gather": "on [fixed]", 
                "tx_scatter_gather_fraglist": "on [fixed]", 
                "tx_sctp_segmentation": "on", 
                "tx_sit_segmentation": "off [fixed]", 
                "tx_tcp6_segmentation": "on", 
                "tx_tcp_ecn_segmentation": "on", 
                "tx_tcp_mangleid_segmentation": "on", 
                "tx_tcp_segmentation": "on", 
                "tx_udp_tnl_csum_segmentation": "off [fixed]", 
                "tx_udp_tnl_segmentation": "off [fixed]", 
                "tx_vlan_offload": "off [fixed]", 
                "tx_vlan_stag_hw_insert": "off [fixed]", 
                "udp_fragmentation_offload": "on", 
                "vlan_challenged": "on [fixed]"
            }, 
            "hw_timestamp_filters": [], 
            "ipv4": {
                "address": "127.0.0.1", 
                "broadcast": "host", 
                "netmask": "255.0.0.0", 
                "network": "127.0.0.0"
            }, 
            "ipv6": [
                {
                    "address": "::1", 
                    "prefix": "128", 
                    "scope": "host"
                }
            ], 
            "mtu": 65536, 
            "promisc": false, 
            "timestamping": [
                "rx_software", 
                "software"
            ], 
            "type": "loopback"
        }, 
        "ansible_local": {}, 
        "ansible_lsb": {}, 
        "ansible_machine": "x86_64", 
        "ansible_machine_id": "6ffc42dc35c88f0599d8226fd104737e", 
        "ansible_memfree_mb": 3174, 
        "ansible_memory_mb": {
            "nocache": {
                "free": 3363, 
                "used": 175
            }, 
            "real": {
                "free": 3174, 
                "total": 3538, 
                "used": 364
            }, 
            "swap": {
                "cached": 0, 
                "free": 0, 
                "total": 0, 
                "used": 0
            }
        }, 
        "ansible_memtotal_mb": 3538, 
        "ansible_mounts": [
            {
                "block_available": 2182863, 
                "block_size": 4096, 
                "block_total": 2618624, 
                "block_used": 435761, 
                "device": "/dev/sda1", 
                "fstype": "xfs", 
                "inode_available": 5186418, 
                "inode_total": 5242368, 
                "inode_used": 55950, 
                "mount": "/", 
                "options": "rw,relatime,attr2,inode64,noquota", 
                "size_available": 8941006848, 
                "size_total": 10725883904, 
                "uuid": "823db525-82d9-467e-acdf-7379cbd85171"
            }
        ], 
        "ansible_nodename": "node1", 
        "ansible_os_family": "RedHat", 
        "ansible_pkg_mgr": "yum", 
        "ansible_processor": [
            "0", 
            "GenuineIntel", 
            "Intel(R) Xeon(R) CPU @ 2.30GHz"
        ], 
        "ansible_processor_cores": 1, 
        "ansible_processor_count": 1, 
        "ansible_processor_threads_per_core": 1, 
        "ansible_processor_vcpus": 1, 
        "ansible_product_name": "Google Compute Engine", 
        "ansible_product_serial": "NA", 
        "ansible_product_uuid": "NA", 
        "ansible_product_version": "NA", 
        "ansible_python": {
            "executable": "/usr/bin/python", 
            "has_sslcontext": true, 
            "type": "CPython", 
            "version": {
                "major": 2, 
                "micro": 5, 
                "minor": 7, 
                "releaselevel": "final", 
                "serial": 0
            }, 
            "version_info": [
                2, 
                7, 
                5, 
                "final", 
                0
            ]
        }, 
        "ansible_python_version": "2.7.5", 
        "ansible_real_group_id": 1001, 
        "ansible_real_user_id": 1000, 
        "ansible_selinux": {
            "status": "disabled"
        }, 
        "ansible_selinux_python_present": true, 
        "ansible_service_mgr": "systemd", 
        "ansible_ssh_host_key_ecdsa_public": "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHvO2e4177+Goy3GrlA6hoCWtw+eX2rbuNs1oiBVt7JT4+DWArHMl0eCAu82JY4IjScKj/6dEz5D+e6Rom7bQCk=", 
        "ansible_ssh_host_key_ed25519_public": "AAAAC3NzaC1lZDI1NTE5AAAAIMLcumVMEmvz6c4DHoMa9H1RS5paRgZoOGi5nalf2vUP", 
        "ansible_ssh_host_key_rsa_public": "AAAAB3NzaC1yc2EAAAADAQABAAABAQCmGyTwoTIoEEDOa2vaic57NUM0SIH4slPR5NHozdRg7Sske0RrFqQs7mgyzW4rpERLBgC085TJAmZ7N1cOGL9qh+umrehJmzdAxH2jWghs5EPxS+9TpXvU2zfHy0npcBQtLG0DGTmhFfp/jbLDGBghpR4rgCdXQlIqeP8nlksIXq3KOR+9uEJ/5JoN+ezdRzpFR571rJiG6Z9VhYbizkzL7eJ0RznvbJw/Ntdq+y9xvKZX7e6mZ1relKdIAxObES5ZbrPPwlIeQbEI/vywYvtMOVoResHE0XWkSB3OV0HLchElDtNM9D3ETTNZK3ij9KHtGRyUtztxhRSmPGdAF2pN", 
        "ansible_swapfree_mb": 0, 
        "ansible_swaptotal_mb": 0, 
        "ansible_system": "Linux", 
        "ansible_system_capabilities": [
            ""
        ], 
        "ansible_system_capabilities_enforced": "True", 
        "ansible_system_vendor": "Google", 
        "ansible_uptime_seconds": 3502, 
        "ansible_user_dir": "/home/ec2-user", 
        "ansible_user_gecos": "", 
        "ansible_user_gid": 1001, 
        "ansible_user_id": "ec2-user", 
        "ansible_user_shell": "/bin/bash", 
        "ansible_user_uid": 1000, 
        "ansible_userspace_architecture": "x86_64", 
        "ansible_userspace_bits": "64", 
        "ansible_virtualization_role": "guest", 
        "ansible_virtualization_type": "kvm", 
        "facter_architecture": "x86_64", 
        "facter_blockdevice_sda_model": "PersistentDisk", 
        "facter_blockdevice_sda_size": 10737418240, 
        "facter_blockdevice_sda_vendor": "Google", 
        "facter_blockdevices": "sda", 
        "facter_dhcp_servers": {
            "eth0": "169.254.169.254", 
            "system": "169.254.169.254"
        }, 
        "facter_domain": "c.my-project-second-211910.internal", 
        "facter_facterversion": "2.4.1", 
        "facter_filesystems": "xfs", 
        "facter_fqdn": "node1.c.my-project-second-211910.internal", 
        "facter_gce": {
            "instance": {
                "attributes": {}, 
                "description": "", 
                "disks": [
                    {
                        "deviceName": "node1", 
                        "index": 0, 
                        "mode": "READ_WRITE", 
                        "type": "PERSISTENT"
                    }
                ], 
                "hostname": "node1.c.my-project-second-211910.internal", 
                "id": 6932256507104413925, 
                "image": "mycentos7", 
                "licenses": [
                    {
                        "id": "1000207"
                    }
                ], 
                "machineType": "n1-standard-1", 
                "maintenanceEvent": "NONE", 
                "name": "node1", 
                "networkInterfaces": [
                    {
                        "accessConfigs": [
                            {
                                "externalIp": "104.196.147.138", 
                                "type": "ONE_TO_ONE_NAT"
                            }
                        ], 
                        "dnsServers": [
                            "169.254.169.254"
                        ], 
                        "forwardedIps": [], 
                        "gateway": "10.142.0.1", 
                        "ip": "10.142.0.6", 
                        "ipAliases": [], 
                        "mac": "42:01:0a:8e:00:06", 
                        "network": "default", 
                        "subnetmask": "255.255.240.0", 
                        "targetInstanceIps": []
                    }
                ], 
                "preempted": "FALSE", 
                "scheduling": {
                    "automaticRestart": "TRUE", 
                    "onHostMaintenance": "MIGRATE", 
                    "preemptible": "FALSE"
                }, 
                "serviceAccounts": {
                    "689469430753-compute@developer.gserviceaccount.com": {
                        "aliases": [
                            "default"
                        ], 
                        "email": "689469430753-compute@developer.gserviceaccount.com", 
                        "scopes": [
                            "https://www.googleapis.com/auth/devstorage.read_only", 
                            "https://www.googleapis.com/auth/logging.write", 
                            "https://www.googleapis.com/auth/monitoring.write", 
                            "https://www.googleapis.com/auth/servicecontrol", 
                            "https://www.googleapis.com/auth/service.management.readonly", 
                            "https://www.googleapis.com/auth/trace.append"
                        ]
                    }, 
                    "default": {
                        "aliases": [
                            "default"
                        ], 
                        "email": "689469430753-compute@developer.gserviceaccount.com", 
                        "scopes": [
                            "https://www.googleapis.com/auth/devstorage.read_only", 
                            "https://www.googleapis.com/auth/logging.write", 
                            "https://www.googleapis.com/auth/monitoring.write", 
                            "https://www.googleapis.com/auth/servicecontrol", 
                            "https://www.googleapis.com/auth/service.management.readonly", 
                            "https://www.googleapis.com/auth/trace.append"
                        ]
                    }
                }, 
                "tags": [], 
                "zone": "us-east1-b"
            }, 
            "oslogin": {}, 
            "project": {
                "attributes": {
                    "ssh-keys": "ec2-user:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/tYQdmDDo8GiZft0T5Dw1bH/Yh/yts+KRaUlSSmeGRDjLOlXu62JuN7QnOH5AvAfQb0oljAEayhqJUgQNWvgxCrykgRxemjh7dSrIDKlae1rYoaEbNCUYNWcx4p/8aJhSkBs/hA+UlPGPQwFzkO2XpC1xZJ1qnQXKDQU7mw1s7r9AjOtt0Qw2O8hnsSssy8d1j457yU3z7EwWBprl17lnl+5kIOROIV7UqLIRtasdhvpMH+pjXd5g/WJK+rFjSl7K+RMaZqV47pXPq9eDIWZF4JOA59yB0wjfoPE0mdA3NhyyZMvXkSRdaABnipXBfthp97lMOAkOxCgsC1bNe2p5 ec2-user"
                }, 
                "numericProjectId": 689469430753, 
                "projectId": "my-project-second-211910"
            }
        }, 
        "facter_gid": "ec2-user", 
        "facter_hardwareisa": "x86_64", 
        "facter_hardwaremodel": "x86_64", 
        "facter_hostname": "node1", 
        "facter_id": "ec2-user", 
        "facter_interfaces": "eth0,lo", 
        "facter_ipaddress": "10.142.0.6", 
        "facter_ipaddress_eth0": "10.142.0.6", 
        "facter_ipaddress_lo": "127.0.0.1", 
        "facter_is_virtual": true, 
        "facter_kernel": "Linux", 
        "facter_kernelmajversion": "3.10", 
        "facter_kernelrelease": "3.10.0-862.6.3.el7.x86_64", 
        "facter_kernelversion": "3.10.0", 
        "facter_macaddress": "42:01:0a:8e:00:06", 
        "facter_macaddress_eth0": "42:01:0a:8e:00:06", 
        "facter_memoryfree": "3.27 GB", 
        "facter_memoryfree_mb": "3351.38", 
        "facter_memorysize": "3.46 GB", 
        "facter_memorysize_mb": "3538.20", 
        "facter_mtu_eth0": 1460, 
        "facter_mtu_lo": 65536, 
        "facter_netmask": "255.255.255.255", 
        "facter_netmask_eth0": "255.255.255.255", 
        "facter_netmask_lo": "255.0.0.0", 
        "facter_network_eth0": "10.142.0.6", 
        "facter_network_lo": "127.0.0.0", 
        "facter_operatingsystem": "CentOS", 
        "facter_operatingsystemmajrelease": "7", 
        "facter_operatingsystemrelease": "7.5.1804", 
        "facter_os": {
            "family": "RedHat", 
            "name": "CentOS", 
            "release": {
                "full": "7.5.1804", 
                "major": "7", 
                "minor": "5"
            }
        }, 
        "facter_osfamily": "RedHat", 
        "facter_partitions": {
            "sda1": {
                "filesystem": "xfs", 
                "label": "/", 
                "mount": "/", 
                "size": "20969472", 
                "uuid": "823db525-82d9-467e-acdf-7379cbd85171"
            }
        }, 
        "facter_path": "/usr/local/bin:/usr/bin", 
        "facter_physicalprocessorcount": 1, 
        "facter_processor0": "Intel(R) Xeon(R) CPU @ 2.30GHz", 
        "facter_processorcount": 1, 
        "facter_processors": {
            "count": 1, 
            "models": [
                "Intel(R) Xeon(R) CPU @ 2.30GHz"
            ], 
            "physicalcount": 1
        }, 
        "facter_ps": "ps -ef", 
        "facter_rubyplatform": "x86_64-linux", 
        "facter_rubysitedir": "/usr/local/share/ruby/site_ruby/", 
        "facter_rubyversion": "2.0.0", 
        "facter_selinux": false, 
        "facter_sshecdsakey": "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHvO2e4177+Goy3GrlA6hoCWtw+eX2rbuNs1oiBVt7JT4+DWArHMl0eCAu82JY4IjScKj/6dEz5D+e6Rom7bQCk=", 
        "facter_sshed25519key": "AAAAC3NzaC1lZDI1NTE5AAAAIMLcumVMEmvz6c4DHoMa9H1RS5paRgZoOGi5nalf2vUP", 
        "facter_sshfp_ecdsa": "SSHFP 3 1 8573e94fd7796251fcb6b2897c5ee42d8da26d48\nSSHFP 3 2 7ae609bf49c814f5327555b277b770934cff1d41cc0893bcac2414b79d116f03", 
        "facter_sshfp_ed25519": "SSHFP 4 1 95c3a3f8ad57f7b9574fbeb42d89352aa23d240b\nSSHFP 4 2 825749114cfe31f7779d710407abfc05e0ba04a8f5d6ff53cd92f1c778f474a2", 
        "facter_sshfp_rsa": "SSHFP 1 1 ca0ca2e6b444fa67099198804e51fd45b60e661e\nSSHFP 1 2 f53764a7484b7360df4d18bee18a9cc5bd3fe9422a82afdf675d940b4565b278", 
        "facter_sshrsakey": "AAAAB3NzaC1yc2EAAAADAQABAAABAQCmGyTwoTIoEEDOa2vaic57NUM0SIH4slPR5NHozdRg7Sske0RrFqQs7mgyzW4rpERLBgC085TJAmZ7N1cOGL9qh+umrehJmzdAxH2jWghs5EPxS+9TpXvU2zfHy0npcBQtLG0DGTmhFfp/jbLDGBghpR4rgCdXQlIqeP8nlksIXq3KOR+9uEJ/5JoN+ezdRzpFR571rJiG6Z9VhYbizkzL7eJ0RznvbJw/Ntdq+y9xvKZX7e6mZ1relKdIAxObES5ZbrPPwlIeQbEI/vywYvtMOVoResHE0XWkSB3OV0HLchElDtNM9D3ETTNZK3ij9KHtGRyUtztxhRSmPGdAF2pN", 
        "facter_swapfree": "0.00 MB", 
        "facter_swapfree_mb": "0.00", 
        "facter_swapsize": "0.00 MB", 
        "facter_swapsize_mb": "0.00", 
        "facter_system_uptime": {
            "days": 0, 
            "hours": 0, 
            "seconds": 3503, 
            "uptime": "0:58 hours"
        }, 
        "facter_timezone": "UTC", 
        "facter_uniqueid": "8e0a0600", 
        "facter_uptime": "0:58 hours", 
        "facter_uptime_days": 0, 
        "facter_uptime_hours": 0, 
        "facter_uptime_seconds": 3503, 
        "facter_virtual": "gce", 
        "gather_subset": [
            "all"
        ], 
        "module_setup": true
    }, 
    "changed": false
