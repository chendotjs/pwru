// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"fmt"
	"regexp"

	"github.com/cilium/ebpf/btf"
)

// skb_try_coalesce
// skb_shift
// skb_split
// skb_append
// skb_zerocopy
// pskb_put
// skb_zerocopy_clone
// skb_morph
// __skb_clone
// rtnl_kfree_skbs
// skb_gro_receive
// ip_copy_metadata
// tcp_collapse
// tcp_try_coalesce
// tcp_skb_shift
// tcp_shifted_skb
// tcp_fragment_tstamp
// bpf_skops_hdr_opt_len
// inet_frag_reasm_prepare
// ip6_copy_metadata
// mptcp_try_coalesce
//
// These funcs have at least two args of type struct sk_buff* . In convention, the last sk_buff arg is the skb we want to trace.

type Funcs map[string]int

// similar to: bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep "FUNC " | less
func GetFuncs(pattern string) (Funcs, error) {
	funcs := Funcs{}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	iter := spec.Iterate()
	for iter.Next() {
		typ := iter.Type
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		fnName := string(fn.Name)

		if pattern != "" && reg.FindString(fnName) != fnName {
			continue
		}

		fnProto := fn.Type.(*btf.FuncProto)
		i := 1
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					// why 5? see https://github.com/cilium/pwru/issues/33
					if strct.Name == "sk_buff" && i <= 5 {
						funcs[fnName] = i
						// log.Printf("found func %s with *sk_buff arg index: %d", fnName, i)
						continue
					}
				}
			}
			i += 1
		}
	}

	return funcs, nil
}
