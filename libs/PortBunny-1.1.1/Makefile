WARN    := -W -Wall -Wstrict-prototypes -Wmissing-prototypes

obj-m += portbunny.o
portbunny-objs := scanner_module.o scan_job_states.o packet_submitter.o scan_job_manager.o\
queue.o scan_jobs.o timespec_utils.o\
\
scanner_ui/scanner_ui.o scanner_ui/scanner_output_queue.o scanner_ui/pending_commands_queue.o scanner_ui/cmd_handlers.o\
\
sniffer/packet_receiver.o sniffer/sniffed_packet.o sniffer/parse_tree.o\
\
trigger_state/state.o trigger_state/trigger_finding_methods.o trigger_state/trigger_instance.o trigger_state/cmd_handlers.o\
trigger_state/icmp_er_method.o trigger_state/icmp_ts_method.o trigger_state/icmp_addr_mask_method.o trigger_state/udp_method.o\
trigger_state/tcp_syn_method.o trigger_state/tcp_ack_method.o trigger_state/ip_prot_method.o\
\
flood_state/cmd_handlers.o flood_state/packet_batch.o flood_state/port_result.o flood_state/state.o\
flood_state/batch_creator.o flood_state/event_reporters.o flood_state/net_info_keeper.o flood_state/trigger_manager.o\
\
flood_state/timing/tcp_reno.o flood_state/timing/tcp_vegas.o flood_state/timing/tcp_scalable.o flood_state/timing/timing.o\
rlimit_detect_state/state.o rlimit_detect_state/cmd_handlers.o



all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	# make -C /usr/src/linux-source-2.6.20 M=$(PWD) modules
	# make -C /lib/modules/2.6.15-28-386/build M=$(PWD) modules
	# make -C /usr/src/linux-headers-2.6.20-16 M=$(PWD) modules	
	# make -C /usr/src/linux-2.6.13.2 M=$(PWD) modules	
	# make -C /usr/src/linux-2.6.14.1 M=$(PWD) modules	
	# make -C /usr/src/linux-2.6.16.1 M=$(PWD) modules	
	# make -C /usr/src/linux-2.6.16.27 M=$(PWD) modules	
	# make -C /usr/src/linux-2.6.16.20 M=$(PWD) modules	
	# make -C /usr/src/linux-2.6.17.1 M=$(PWD) modules	
	# make -C /usr/src/linux-2.6.26.3 M=$(PWD) modules


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	# make -C /usr/src/linux-source-2.6.20 M=$(PWD) clean
	# make -C /lib/modules/2.6.15-28-386/build M=$(PWD) clean
	# make -C /usr/src/linux-headers-2.6.20-16 M=$(PWD) clean	
	# make -C /usr/src/linux-2.6.12.2 M=$(PWD) clean	
	# make -C /usr/src/linux-2.6.14.1 M=$(PWD) clean	
	# make -C /usr/src/linux-2.6.16.1 M=$(PWD) clean	
	# make -C /usr/src/linux-2.6.16.27 M=$(PWD) clean	
	# make -C /usr/src/linux-2.6.16.20 M=$(PWD) clean	
	# make -C /usr/src/linux-2.6.17.1 M=$(PWD) clean	

install:
	
	$(shell install -m 644 portbunny.ko /lib/modules/$(shell uname -r)/kernel/portbunny.ko; /sbin/depmod -a)	
	$(shell cp -r ./UI/* /usr/local/)
