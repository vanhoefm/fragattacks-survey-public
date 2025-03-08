from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

int kprobe__ieee80211_is_valid_amsdu(struct pt_regs *ctx) {
	//struct sk_buff *skb; // = (struct sk_buff *)PT_REGS_PARM1(ctx);
	long long mesh_hdr = (u8)PT_REGS_PARM2(ctx);

	//bpf_get_func_arg(ctx, 0, &skb);
	//bpf_get_func_arg(ctx, 1, &mesh_hdr);

	bpf_trace_printk("ieee80211_is_valid_amsdu hit: %d\\n", mesh_hdr);

	return 0;
}


int hook_return(struct pt_regs *ctx) {
	//struct sk_buff *skb; // = (struct sk_buff *)PT_REGS_PARM1(ctx);
	int rval = (int)PT_REGS_RC(ctx);

	//bpf_get_func_arg(ctx, 0, &skb);
	//bpf_get_func_arg(ctx, 1, &mesh_hdr);

	bpf_trace_printk("ieee80211_is_valid_amsdu returned: %d\\n", rval);

	return 0;
}
"""

b = BPF(text=bpf_source)
b.attach_kretprobe(event="ieee80211_is_valid_amsdu", fn_name="hook_return")

print("Tracing ieee80211_is_valid_amsdu... Press Ctrl+C to stop.")

try:
    while True:
        msg = b.trace_fields()
        print(msg)
except KeyboardInterrupt:
    print("Detaching BPF program...")

